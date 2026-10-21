"""Background jobs for long-running scans (unallocated grep, content grep, recovery)."""
from __future__ import annotations
import threading, time, traceback, uuid

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def start(kind: str, fn, **kwargs) -> dict:
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "kind": kind, "status": "running", "started": time.time(), "finished": None, "progress": "", "args": {k: v for k, v in kwargs.items() if k != "progress"}, "result": None, "error": None}
    with _lock:
        _jobs[jid] = job

    def progress(msg: str):
        job["progress"] = msg

    def runner():
        try:
            job["result"] = fn(progress=progress, **kwargs)
            job["status"] = "done"
        except Exception as e:  # noqa
            job["error"] = f"{e}\n{traceback.format_exc()[-1500:]}"
            job["status"] = "failed"
        job["finished"] = time.time()

    threading.Thread(target=runner, daemon=True).start()
    return {"job_id": jid, "status": "running", "kind": kind}


def status(jid: str) -> dict:
    j = _jobs.get(jid)
    if not j:
        return {"error": f"no job {jid}"}
    d = {k: j[k] for k in ("id", "kind", "status", "progress", "args", "error")}
    d["elapsed_s"] = round((j["finished"] or time.time()) - j["started"], 1)
    return d


def result(jid: str, wait_s: int = 0) -> dict:
    j = _jobs.get(jid)
    if not j:
        return {"error": f"no job {jid}"}
    t_end = time.time() + wait_s
    while j["status"] == "running" and time.time() < t_end:
        time.sleep(1)
    d = status(jid)
    if j["status"] == "done":
        d["result"] = j["result"]
    return d


def list_jobs() -> list[dict]:
    return [status(j) for j in list(_jobs)]
