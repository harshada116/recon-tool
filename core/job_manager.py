"""In-memory async job tracking so the HTTP request returns immediately
while modules like WHOIS/subdomain enum run in the background.

For a single-process demo this in-memory dict is fine. For production
(multiple workers, restarts), back this with Redis and use Celery
instead of a bare thread pool.
"""

import threading
import uuid
from datetime import datetime, timezone

_JOBS = {}
_LOCK = threading.Lock()


def create_job() -> str:
    job_id = str(uuid.uuid4())
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "modules_total": 0,
            "modules_complete": 0,
            "report": None,
            "error": None,
        }
    return job_id


def get_job(job_id: str):
    with _LOCK:
        return _JOBS.get(job_id)


def update_job(job_id: str, **kwargs):
    with _LOCK:
        if job_id in _JOBS:
            _JOBS[job_id].update(kwargs)


def run_job_async(job_id: str, target: dict, options: dict):
    """Runs the recon scan in a background thread, updating job status as
    modules complete, and stores the final report on the job when done."""
    from core.orchestrator import ANALYZER_MODULES, OPTIONAL_MODULES, _run_one
    from core.report_builder import build_report
    from concurrent.futures import ThreadPoolExecutor, as_completed

    modules_to_run = list(ANALYZER_MODULES)
    if options.get("port_scan") and options.get("port_scan_authorized"):
        modules_to_run.append(OPTIONAL_MODULES["port_scan"])

    update_job(job_id, status="running", modules_total=len(modules_to_run), modules_complete=0)

    results = []
    try:
        with ThreadPoolExecutor(max_workers=max(1, len(modules_to_run))) as pool:
            futures = {pool.submit(_run_one, m, target): m for m in modules_to_run}
            for future in as_completed(futures):
                results.append(future.result())
                job = get_job(job_id)
                update_job(job_id, modules_complete=(job["modules_complete"] + 1) if job else 1)

        order = {getattr(m, "MODULE_NAME", m.__name__): i for i, m in enumerate(modules_to_run)}
        results.sort(key=lambda r: order.get(r["module"], 999))

        report = build_report(target, results, options)
        update_job(job_id, status="complete", report=report)
    except Exception as exc:  # noqa: BLE001 - never let the background thread die silently
        update_job(job_id, status="error", error=str(exc))


def start_scan(target: dict, options: dict) -> str:
    job_id = create_job()
    thread = threading.Thread(target=run_job_async, args=(job_id, target, options), daemon=True)
    thread.start()
    return job_id
