#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 后台任务状态（供前端「提交 + 轮询」）

有些操作天然比一次 HTTP 请求活得久：GitHub 在线升级要下载几十 MB 并覆盖
几百个文件，AI 连接测试要等模型回包（超时上限 120s）。它们跑在请求线程里
时，反向代理/面板的 60s 超时先到——用户看到「失败」，后台其实成功了
（升级场景会反复点，AI 场景会并发打模型）。

本模块把这套「任务文件 + 轮询」从 frp.py 的安装任务里抽出来通用化，
只负责三件事：

  1. 状态原子落盘（data/job_<kind>.json），跨线程、跨进程、跨重启可读；
  2. 心跳时间戳 + 僵死判定：后台线程随面板重启消失时，状态能自证「已中断」，
     而不是永远卡在 running=True；
  3. 按 kind 串行化：同一类任务同一时刻只允许一个在跑（并发保护）。

字段契约（前端据此渲染进度，新增字段只追加不改语义）：
    job_id    本次任务标识（字符串，提交时返回给前端做对账）
    running   是否正在执行
    percent   0-100 的粗略进度
    msg       给用户看的中文阶段说明（进行中/成功都用它）
    done      是否已结束（成功、失败、中断都置 True）
    ok        结束时是否成功（未结束时恒为 False）
    error     失败原因（成功时为空串）
    ts        心跳时间戳（秒），供僵死判定，前端可忽略
    started   开始时间戳（秒）
    finished  结束时间戳（秒，未结束为 0）
    ms        总耗时（毫秒，未结束为 0）

注意：本模块不写日志、不碰业务配置，只做状态存取；失败的原因由调用方的
worker 返回，避免在这里吞掉异常（后台线程静默失败是最难排查的一类问题）。
"""
import json
import os
import threading
import time
import traceback

from . import config

# 心跳间隔（秒）与僵死判定阈值（秒）。
# 阈值取 6 个心跳：单次落盘抖动（磁盘忙、GC）不会误判，真死掉的线程
# 也能在 1 分钟内被前端看出来。
HEARTBEAT = 10
STALE = 60

# 逐 kind 串行：状态文件的读写同时受这把锁保护（仅进程内）。
# 跨进程**不**受这把锁约束：守护进程（/api/*）与宝塔插件端（s= 方法）都会
# 写同一个 data/job_*.json。两个写入方并不是同一时刻高频竞争（都是人手点的
# 长任务，且 start 前会先看 running），所以没引入文件锁；代价是极端情况下
# 两边同时 start 同一 kind，可能出现「两个任务都跑」的窄窗口。
_lock = threading.RLock()

_EMPTY = {
    "job_id": "", "kind": "", "running": False, "percent": 0, "msg": "",
    "done": False, "ok": False, "error": "", "ts": 0, "started": 0,
    "finished": 0, "ms": 0,
}


def _safe_kind(kind):
    """kind 会拼进文件名：只允许 [a-z0-9_]，杜绝路径穿越。"""
    s = str(kind or "").strip().lower()
    out = "".join(c for c in s if c.isalnum() or c == "_")
    if not out or out != s:
        raise ValueError("非法任务类型：%r" % (kind,))
    return out


def path(kind):
    """任务状态文件路径（data/job_<kind>.json）。

    kind 先过白名单过滤（只留 [a-z0-9_]），再校验最终路径仍在 DATA_DIR 内；
    两道防线都保留，避免以后有人放宽过滤时直接变成任意文件写入。
    """
    name = "job_%s.json" % _safe_kind(kind)
    full = os.path.abspath(os.path.join(config.DATA_DIR, name))
    if os.path.dirname(full) != os.path.abspath(config.DATA_DIR) or \
            os.path.basename(full) != name:
        raise ValueError("非法任务状态路径：%r" % (name,))
    return full


def _write(kind, state):
    """原子写状态：临时文件 + os.replace，避免前端读到半截 JSON。"""
    p = path(kind)
    tmp = "%s.tmp.%d.%d" % (p, os.getpid(), threading.get_ident())
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
        return True
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def _read(kind):
    """读状态（不判定僵死，调用方决定）。读不到返回空状态副本。"""
    st = dict(_EMPTY)
    st["kind"] = _safe_kind(kind)
    try:
        with open(path(kind), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                st[k] = v
    except (OSError, ValueError):
        pass
    return st


def _stale(st):
    """running 但心跳超时：后台线程已随进程消失（面板重启/被 kill）。"""
    if not st.get("running"):
        return False
    try:
        return (time.time() - int(st.get("ts") or 0)) > STALE
    except (TypeError, ValueError):
        return True


def _mark_stale(st):
    """把僵死任务改写成「已结束但失败」，让前端能收尾而不是无限转圈。

    注意这判定的两种成因无法区分：后台线程真挂了，或任务已执行完但服务
    在写最终状态前被重启（升级末尾就含重启）。所以文案说「中断或已重启」，
    让用户去确认最终结果，而不是断言「一定失败」。
    """
    msg = "任务状态已中断（服务可能重启过），请刷新页面确认最终结果"
    st.update({"running": False, "done": True, "ok": False, "error": msg,
               "msg": msg, "finished": int(time.time())})
    _write(st.get("kind") or "", st)
    return st


def status(kind):
    """读回任务状态（含僵死判定与自愈写回）。"""
    with _lock:
        st = _read(kind)
        if _stale(st):
            st = _mark_stale(st)
        return st


def clear(kind):
    """清掉状态文件（测试/排障用；正常流程不需要）。"""
    with _lock:
        try:
            os.remove(path(kind))
        except OSError:
            pass


def busy(kind):
    """是否有任务正在执行（僵死任务不算，避免一次面板重启后永久拒绝提交）。"""
    return bool(status(kind).get("running"))


def start(kind, worker, msg="准备中…", job_id=""):
    """提交后台任务。

    worker: 可调用对象，签名为 worker(progress) -> dict；返回值里可带
            ok / msg / error，以及任意附加字段（会原样并入状态，便于前端取用）。
            progress(percent, msg) 用于在长任务里推进进度；内部任务抛出的
            任何异常都会被抓成 ok=False + error，不会静默消失。
    job_id: 可指定（测试用），留空自动生成。

    返回 (ok, 说明, 状态)；已有同类任务在跑时 ok=False 且不启动线程。
    """
    now = int(time.time())
    with _lock:
        st = _read(kind)
        if _stale(st):
            st = _mark_stale(st)
        if st.get("running"):
            return False, "已有任务在进行中（%s），请等待完成" % (st.get("msg") or "处理中"), st
        if not job_id:
            job_id = "%s-%d-%04x" % (_safe_kind(kind), now, int(time.time() * 1000) % 0x10000)
        state = dict(_EMPTY)
        state.update({
            "job_id": job_id, "kind": _safe_kind(kind), "running": True,
            "percent": 0, "msg": msg, "done": False, "ok": False, "error": "",
            "ts": now, "started": now, "finished": 0, "ms": 0,
        })
        if not _write(kind, state):
            return False, "任务状态写入失败（请检查 data/ 目录权限与磁盘空间）", state

    th = threading.Thread(target=_supervise, args=(kind, job_id, worker),
                          name="frpwaf-job-" + _safe_kind(kind), daemon=True)
    th.start()
    return True, "已提交", state


def _reporter(kind, job_id):
    """生成进度回调：只在「状态仍属于本次任务」时写入，避免覆盖后来的任务。"""
    def _progress(percent=None, msg=None):
        with _lock:
            st = _read(kind)
            if st.get("job_id") != job_id:
                return
            if percent is not None:
                try:
                    st["percent"] = max(0, min(100, int(percent)))
                except (TypeError, ValueError):
                    pass
            if msg is not None:
                st["msg"] = str(msg)
            st["ts"] = int(time.time())
            _write(kind, st)
    return _progress


def _supervise(kind, job_id, worker):
    """执行 worker 并维护心跳：worker 跑在子线程，本线程只负责保活。

    单独起子线程是为了心跳——若 worker 一次调用卡住 100 秒（下载大包/模型
    迟迟不回），主循环仍能每 10 秒刷新 ts，状态不会被误判成「已中断」。
    """
    out = {}

    def _run():
        try:
            res = worker(_reporter(kind, job_id))
            out["res"] = res if isinstance(res, dict) else {}
        except Exception:
            out["exc"] = traceback.format_exc()

    t = threading.Thread(target=_run, name="frpwaf-job-run-" + _safe_kind(kind),
                         daemon=True)
    t.start()
    while t.is_alive():
        t.join(HEARTBEAT)
        if not t.is_alive():
            break
        with _lock:
            st = _read(kind)
            if st.get("job_id") != job_id:
                return          # 状态被后来的任务接管：本次不再写入
            st["ts"] = int(time.time())
            _write(kind, st)

    now = int(time.time())
    with _lock:
        st = _read(kind)
        if st.get("job_id") != job_id:
            return
        started = int(st.get("started") or now)
        st["finished"] = now
        st["ms"] = max(0, (now - started) * 1000)
        st["ts"] = now
        st["running"] = False
        st["done"] = True
        if out.get("exc"):
            tail = out["exc"].strip().splitlines()[-1][:300]
            st["ok"] = False
            st["error"] = "后台任务异常：" + tail
            st["msg"] = st["error"]
        else:
            res = out.get("res") or {}
            st["ok"] = bool(res.get("ok"))
            st["error"] = str(res.get("error") or "")
            st["msg"] = str(res.get("msg") or ("已完成" if st["ok"] else
                                               (st["error"] or "任务失败（未返回原因，请查看运行日志）")))
            if st["ok"]:
                st["percent"] = 100
            # worker 返回的附加字段（如 from/to/sha256）原样并入，便于前端展示
            for k, v in res.items():
                if k in ("ok", "msg", "error", "running", "done", "percent", "ts",
                         "started", "finished", "ms", "job_id", "kind"):
                    continue
                st[k] = v
        _write(kind, st)
