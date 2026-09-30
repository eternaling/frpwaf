#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - AI 自动 IP 审查

周期性把最近一段时间的高频来源 IP（含归属地、连接数、命中代理）汇总后，
交给大模型判断是否恶意，并按判定分级处置：

  - 确凿（malicious）        -> 永久黑名单（ip_list black，内核 timeout=0）
  - 疑似（suspicious）       -> 临时封禁（时长 ai_ban_seconds，默认 1800 秒）
  - SSH 相关从严             -> 模型标记 SSH 爆破、或命中代理名含 ssh 时，
                                疑似也直接永久黑名单（ai_ssh_strict 控制）
  - 白名单命中 / 已处置      -> 跳过（skipped / already_banned）

支持两种协议：
  - openai    : POST {base}/v1/chat/completions   (Authorization: Bearer)
  - anthropic : POST {base}/v1/messages           (x-api-key + anthropic-version)
仅使用标准库 urllib，无需额外依赖。
"""
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request

from . import config, geo, store

SYSTEM_PROMPT = (
    "你是一名服务器安全分析师，负责审查反向代理(frp)的入站连接来源 IP。"
    "你会收到一组来源 IP 及其归属地、连接次数、命中的代理端口类型等信息。"
    "请判断每个 IP 是否属于恶意/可疑行为（例如：端口扫描、SSH 暴力破解、"
    "爬虫抓取、异常高频访问、来自高风险地区的自动化攻击等）。"
    "正常用户访问（如本人手机/公司网络的常规访问、CDN/云服务回源）应判为 benign。"
    "对每个 IP 还需给出攻击类型 category（英文短语，如 ssh_bruteforce、port_scan、"
    "web_scan、crawler、rate_abuse、other；正常访问填 none）。"
    "只输出 JSON，不要输出任何多余文字或 markdown 代码块。"
)


def _build_user_prompt(items):
    lines = [
        "以下是需要审查的来源 IP 列表（JSON）：",
        json.dumps(items, ensure_ascii=False),
        "",
        "请对每个 IP 给出判断，严格按如下 JSON 数组格式返回（不要 markdown 代码块）：",
        '[{"ip":"1.2.3.4","verdict":"malicious|suspicious|benign",'
        '"category":"ssh_bruteforce|port_scan|web_scan|crawler|rate_abuse|other|none",'
        '"reason":"简短中文理由"}]',
        "判定规则：确凿的攻击/扫描/爆破 => malicious；可疑但不确定 => suspicious；正常 => benign。",
        "category 必须是上述取值之一；无法归类时填 other；正常访问填 none。",
    ]
    return "\n".join(lines)


def _collect():
    """汇总最近窗口内的高频 IP。"""
    cfg = config.get()
    window = max(30, int(cfg.get("ai_window") or 300))
    min_conns = max(1, int(cfg.get("ai_min_conns") or 20))
    max_ips = max(1, int(cfg.get("ai_max_ips") or 20))
    since = int(time.time()) - window

    rows = store._query(
        "SELECT ip, COUNT(*) AS conns, "
        "  SUM(CASE WHEN action!='allow' THEN 1 ELSE 0 END) AS rejected, "
        "  GROUP_CONCAT(DISTINCT proxy_name) AS proxies "
        "FROM conn_log WHERE ts>=? GROUP BY ip HAVING conns>=? "
        "ORDER BY conns DESC LIMIT ?",
        (since, min_conns, max_ips),
    )
    items = []
    for r in rows:
        g = geo.lookup(r["ip"])
        items.append({
            "ip": r["ip"],
            "geo": g.get("text", ""),
            "conns": r["conns"],
            "rejected": r["rejected"] or 0,
            "proxies": (r["proxies"] or "")[:120],
        })
    return items


def _extract_json(text):
    """从模型回复中提取 JSON 数组（容忍 markdown 代码块/多余文字）。"""
    if not text:
        return None
    t = text.strip()
    # 去掉 ```json ... ``` 包裹
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    # 找到第一个 [ 到最后一个 ]
    a, b = t.find("["), t.rfind("]")
    if a != -1 and b != -1 and b > a:
        t = t[a:b + 1]
    try:
        return json.loads(t)
    except Exception:
        return None


def _is_whitelisted(ip):
    """IP 是否落在白名单内（白名单优先：AI 不对其自动处置）。

    名单条目可能是 CIDR；判定失败按「不在白名单」处理，不影响主流程。
    """
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for r in store.list_ips("white"):
        try:
            if obj in ipaddress.ip_network(r.get("cidr", ""), strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_ssh_related(category, reason, proxies):
    """判断是否为 SSH 相关（模型标记 SSH 爆破 / 理由或代理名含 ssh）。

    category 缺失（旧模型输出）时用理由与代理名兜底；代理名如 `ssh_22`
    是「经 frp 暴露 SSH 隧道」的强信号，属用户要求的从严范围。
    """
    cat = (category or "").lower()
    if cat in ("ssh_bruteforce", "ssh_brute_force", "ssh_bruteforce_attempt",
               "ssh_attack", "ssh_login"):
        return True
    text = ((category or "") + " " + (reason or "") + " " + (proxies or "")).lower()
    return "ssh" in text


def _apply_action(ip, verdict, category, reason, it, cfg):
    """按判定分级处置并写入审查记录，返回展示用结果字典。

    分级：
      - 确凿（malicious）或 SSH 相关疑似（ai_ssh_strict）-> 永久黑名单
      - 疑似（suspicious，ai_suspicious_ban）           -> 临时封禁
      - 其余 / 已在处置中                                -> 仅记录
    安全边界：白名单命中的 IP 一律不自动处置，防止模型误判导致
    「封 IP 段连坐白名单」；写入前统一校验 IP 合法性。
    """
    ssh = _is_ssh_related(category, reason, it.get("proxies", ""))
    # 白名单优先：即使模型判恶意也不自动处置
    if _is_whitelisted(ip):
        store.add_ai_review(0, ip, verdict, "白名单命中，跳过自动处置", "skipped",
                            cfg.get("ai_model", ""))
        return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
                "action": "skipped", "mode": "whitelist", "ssh": ssh,
                "geo": it.get("geo", ""), "conns": it.get("conns", 0)}

    if not cfg.get("ai_auto_ban"):
        action, mode = "none", ""
    else:
        permanent = (verdict == "malicious") or (
            verdict == "suspicious" and ssh and cfg.get("ai_ssh_strict", True)
            and cfg.get("ai_ssh_permanent_suspicious", True))
        temporary = (verdict == "suspicious" and not permanent
                     and cfg.get("ai_suspicious_ban", True))
        if not (permanent or temporary):
            action, mode = "none", ""
        else:
            # 处置前校验：非法 IP 不进入任何封禁集合
            try:
                ipaddress.ip_network(ip, strict=False)
            except ValueError:
                store.add_ai_review(0, ip, verdict, "IP 格式非法，跳过", "none",
                                    cfg.get("ai_model", ""))
                return {"ip": ip, "verdict": verdict, "category": category,
                        "reason": reason, "action": "none", "mode": "",
                        "ssh": ssh, "geo": it.get("geo", ""),
                        "conns": it.get("conns", 0)}
            if permanent:
                # 确凿 / SSH 从严 -> 永久黑名单（ip_list black，内核 timeout=0）
                try:
                    store.add_ip(ip, "black", ("ai: " + (reason or "malicious"))[:200])
                    action, mode = "permanent", "permanent"
                except ValueError:
                    # 已存在于黑名单（UNIQUE 约束）视为已处置
                    action, mode = "already_banned", "permanent"
                except Exception:
                    action, mode = "ban_failed", "permanent"
                if action != "ban_failed":
                    # 永久生效后释放同名临时封禁（无记录时为无副作用操作）
                    try:
                        store.unban_ip(ip)
                    except Exception:
                        pass
            else:
                # 疑似 -> 临时封禁（ban_log，到期自动释放）
                try:
                    if store.is_banned(ip):
                        action, mode = "already_banned", "temp"
                    else:
                        store.add_ban(ip, ("ai: " + (reason or "suspicious"))[:200],
                                      int(cfg.get("ai_ban_seconds") or 1800))
                        action, mode = "banned", "temp"
                except Exception:
                    action, mode = "ban_failed", "temp"

    store.add_ai_review(0, ip, verdict, reason, action, cfg.get("ai_model", ""))
    return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
            "action": action, "mode": mode, "ssh": ssh,
            "geo": it.get("geo", ""), "conns": it.get("conns", 0)}


def _endpoint(base, path):
    """智能拼接接口地址，兼容用户不同填法，避免出现 /v1/v1/...：

    path 形如 "/v1/chat/completions" 或 "/v1/messages"。
      base = http://host            -> http://host/v1/chat/completions
      base = http://host/v1         -> http://host/v1/chat/completions
      base = http://host/v1/        -> http://host/v1/chat/completions
      base = http://host/v1/chat/completions -> 原样返回
    """
    b = (base or "").strip().rstrip("/")
    if not b:
        return b
    if b.endswith(path):
        return b
    i = path.find("/", 1)
    version, tail = path[:i], path[i:]  # 如 "/v1", "/chat/completions"
    if b.endswith(version):
        return b + tail
    return b + path


def _call_openai(cfg, user_prompt, timeout=60):
    url = _endpoint(cfg["ai_base_url"], "/v1/chat/completions")
    payload = {
        "model": cfg["ai_model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 1500,
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + cfg["ai_api_key"]},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _call_anthropic(cfg, user_prompt, timeout=60):
    url = _endpoint(cfg["ai_base_url"], "/v1/messages")
    payload = {
        "model": cfg["ai_model"],
        "max_tokens": 1500,
        "temperature": 0.1,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "x-api-key": cfg["ai_api_key"],
                 "anthropic-version": "2023-06-01"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    parts = data.get("content") or []
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text")


def call_model(cfg, items):
    """调用大模型，返回 (ok, verdicts_or_error)。"""
    user_prompt = _build_user_prompt(items)
    proto = (cfg.get("ai_protocol") or "openai").lower()
    try:
        timeout = max(15, int(cfg.get("ai_timeout") or 120))
    except (TypeError, ValueError):
        timeout = 120
    last_err = None
    # 网关可能较慢，超时/网络类错误重试一次
    for attempt in (1, 2):
        try:
            if proto == "anthropic":
                text = _call_anthropic(cfg, user_prompt, timeout=timeout)
            else:
                text = _call_openai(cfg, user_prompt, timeout=timeout)
            last_err = None
            break
        except urllib.error.HTTPError as e:
            # HTTP 层错误（如 4xx/5xx）不重试，直接返回
            try:
                detail = e.read().decode("utf-8")[:300]
            except Exception:
                detail = ""
            return False, "HTTP %s %s %s" % (e.code, e.reason, detail)
        except Exception as e:
            last_err = "调用失败: %s" % e
            if attempt == 1:
                time.sleep(2)
                continue
    if last_err:
        return False, last_err

    verdicts = _extract_json(text)
    if verdicts is None:
        return False, "模型返回无法解析为 JSON: %s" % (text or "")[:200]
    if not isinstance(verdicts, list):
        return False, "模型返回不是数组"
    return True, verdicts


def review(force=False):
    """执行一次审查。返回结果字典。"""
    cfg = config.get()
    if not cfg.get("ai_enabled") and not force:
        return {"ok": False, "msg": "AI 审查未启用"}
    if not cfg.get("ai_base_url") or not cfg.get("ai_api_key"):
        return {"ok": False, "msg": "未配置 AI 接口地址或密钥"}

    items = _collect()
    if not items:
        store.add_ai_review(0, "-", "none", "窗口内无达到阈值的 IP", "skip", cfg.get("ai_model", ""))
        return {"ok": True, "msg": "本次无可审查的 IP", "results": [], "checked": 0}

    ok, res = call_model(cfg, items)
    if not ok:
        store.add_ai_review(0, "-", "error", str(res)[:400], "error", cfg.get("ai_model", ""))
        return {"ok": False, "msg": str(res), "results": []}

    # 建立 IP -> 统计 映射，便于展示
    stat = {it["ip"]: it for it in items}
    results = []
    banned = 0        # 永久黑名单数
    temp_banned = 0   # 临时封禁数
    for v in res:
        if not isinstance(v, dict):
            continue
        ip = str(v.get("ip", "")).strip()
        verdict = str(v.get("verdict", "")).strip().lower()
        category = str(v.get("category", "")).strip().lower()
        reason = str(v.get("reason", "")).strip()[:300]
        if not ip:
            continue
        # 只处理本次真正送审过的 IP。模型可能因幻觉 / 提示注入返回集合外的
        # IP（例如被审查内容里诱导出的无关地址），若对其自动封禁可被滥用。
        if ip not in stat:
            continue
        if verdict not in ("malicious", "suspicious", "benign"):
            verdict = "unknown"
        r = _apply_action(ip, verdict, category, reason, stat[ip], cfg)
        if r["action"] == "permanent":
            banned += 1
        elif r["action"] == "banned" and r["mode"] == "temp":
            temp_banned += 1
        results.append(r)

    # 永久黑名单写入后立即让决策缓存失效（名单缓存 3s TTL，改完即生效）；
    # 内核同步由 daemon 后台线程兜底，也可由此处主动触发。
    if banned:
        try:
            from . import engine
            engine.invalidate_cache()
        except Exception:
            pass
        try:
            from . import firewall
            if cfg.get("fw_sync_enabled", True):
                firewall.sync_from_store()
        except Exception:
            pass

    # 更新配置里的上次运行信息
    cfg = config.get()
    cfg["ai_last_run"] = int(time.time())
    cfg["ai_last_result"] = "审查 %d 个 IP，永久黑名单 %d 个，临时封禁 %d 个" % (
        len(results), banned, temp_banned)
    config.save(cfg)
    return {"ok": True, "msg": cfg["ai_last_result"], "results": results,
            "checked": len(items), "banned": banned, "temp_banned": temp_banned}


def loop_forever():
    """后台线程：按间隔执行审查。"""
    while True:
        try:
            cfg = config.get()
            if cfg.get("ai_enabled"):
                interval = max(60, int(cfg.get("ai_interval") or 300))
                last = int(cfg.get("ai_last_run") or 0)
                if time.time() - last >= interval:
                    review()
        except Exception:
            pass
        time.sleep(20)
