#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - AI 自动 IP 审查

周期性把最近一段时间的高频来源 IP（含归属地、连接数、命中代理）汇总后，
交给大模型判断是否恶意，可选自动封禁。

支持两种协议：
  - openai    : POST {base}/v1/chat/completions   (Authorization: Bearer)
  - anthropic : POST {base}/v1/messages           (x-api-key + anthropic-version)
仅使用标准库 urllib，无需额外依赖。
"""
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
    "只输出 JSON，不要输出任何多余文字或 markdown 代码块。"
)


def _build_user_prompt(items):
    lines = [
        "以下是需要审查的来源 IP 列表（JSON）：",
        json.dumps(items, ensure_ascii=False),
        "",
        "请对每个 IP 给出判断，严格按如下 JSON 数组格式返回（不要 markdown 代码块）：",
        '[{"ip":"1.2.3.4","verdict":"malicious|suspicious|benign","reason":"简短中文理由"}]',
        "判定规则：确凿的攻击/扫描/爆破 => malicious；可疑但不确定 => suspicious；正常 => benign。",
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
    banned = 0
    for v in res:
        if not isinstance(v, dict):
            continue
        ip = str(v.get("ip", "")).strip()
        verdict = str(v.get("verdict", "")).strip().lower()
        reason = str(v.get("reason", "")).strip()[:300]
        if not ip:
            continue
        # 只处理本次真正送审过的 IP。模型可能因幻觉 / 提示注入返回集合外的
        # IP（例如被审查内容里诱导出的无关地址），若对其自动封禁可被滥用。
        if ip not in stat:
            continue
        it = stat.get(ip, {})
        action = "none"
        if verdict == "malicious" and cfg.get("ai_auto_ban"):
            # 已在封禁中的 IP 不重复封禁：否则每个审查周期都会重新 add_ban，
            # 不断把封禁到期时间往后顺延（曾出现同一 IP 被连封 19 次）。
            try:
                already = store.is_banned(ip)
            except Exception:
                already = False
            if already:
                action = "already_banned"
            else:
                try:
                    store.add_ban(ip, "ai: " + (reason or "malicious"),
                                  int(cfg.get("ai_ban_seconds") or 1800))
                    action = "banned"
                    banned += 1
                except Exception:
                    action = "ban_failed"
        store.add_ai_review(0, ip, verdict or "unknown", reason, action, cfg.get("ai_model", ""))
        results.append({
            "ip": ip, "verdict": verdict, "reason": reason, "action": action,
            "geo": it.get("geo", ""), "conns": it.get("conns", 0),
        })

    # 更新配置里的上次运行信息
    cfg = config.get()
    cfg["ai_last_run"] = int(time.time())
    cfg["ai_last_result"] = "审查 %d 个 IP，封禁 %d 个" % (len(results), banned)
    config.save(cfg)
    return {"ok": True, "msg": cfg["ai_last_result"], "results": results,
            "checked": len(items), "banned": banned}


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
