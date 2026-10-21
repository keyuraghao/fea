"""Background jobs for long-running scans (unallocated grep, content grep, recovery)."""
from __future__ import annotations

import threading
import time
import traceback
import uuid

MAX_JOBS = 50
_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def _prune() -> None:
    finished = [j for j in _jobs.values() if j["status"] != "running"]
    finished.sort(key=lambda j: j["finished"] or 0)
    while len(_jobs) > MAX_JOBS and finished:
        _jobs.pop(finished.pop(0)["id"], None)


def start(kind: str, fn, **kwargs) -> dict:
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "kind": kind, "status": "running", "started": time.time(), "finished": None, "progress": "",
           "args": {k: v for k, v in kwargs.items() if k != "progress"}, "result": None, "error": None, "cancel": threading.Event()}
    with _lock:
        _jobs[jid] = job
        _prune()

    def progress(msg: str):
        job["progress"] = msg
        if job["cancel"].is_set():
            raise InterruptedError("cancelled")

    def runner():
        try:
            job["result"] = fn(progress=progress, **kwargs)
            job["status"] = "done"
        except InterruptedError:
            job["status"] = "cancelled"
        except Exception as e:  # noqa
            job["error"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-1200:]}"
            job["status"] = "failed"
        job["finished"] = time.time()

    threading.Thread(target=runner, daemon=True, name=f"fea-job-{jid}").start()
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
    t_end = time.time() + max(0, min(wait_s, 300))
    while j["status"] == "running" and time.time() < t_end:
        time.sleep(0.5)
    d = status(jid)
    if j["status"] == "done":
        d["result"] = j["result"]
    return d


def cancel(jid: str) -> dict:
    j = _jobs.get(jid)
    if not j:
        return {"error": f"no job {jid}"}
    j["cancel"].set()
    return {"id": jid, "cancel_requested": True, "status": j["status"]}


def list_jobs() -> list[dict]:
    return [status(j) for j in list(_jobs)]
