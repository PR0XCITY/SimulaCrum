"""Background Certify jobs for the Builder.

A full analysis of a large design can take minutes (Terraform plan + MiniStack apply +
Infracost), longer than a browser keeps one HTTP request open. So
POST /architectures/certify starts a job and returns at once, and the dashboard polls
GET /jobs/{id} until the certificate is stored.

- One worker: shadow runs share one MiniStack, so jobs run one at a time, in order.
- The same architecture submitted again while its job is queued or running gets that
  job back, so a double click or a Retry never certifies the same design twice.
- Jobs live in memory (the last MAX_JOBS); certificates are what persists, in SQLite.
  After an API restart an old job id answers 404 and the certificate list is the truth.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

log = logging.getLogger("ghostops.jobs")
MAX_JOBS = 100
ACTIVE = ("queued", "running")


class JobManager:
    def __init__(self, run: Callable[[dict[str, Any]], dict[str, Any]],
                 on_error: Callable[[Exception], str], *, keep_result: bool = False, name: str = "certify"):
        """run(architecture) -> stored certificate; on_error(exc) -> message for the dashboard.
        keep_result: the job also returns run()'s whole result (the advisor), not just plan_id/verdict."""
        self._run = run
        self._on_error = on_error
        self._keep_result = keep_result
        self._name = name
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=name)

    @staticmethod
    def _key(architecture: dict[str, Any]) -> str:
        return json.dumps(architecture, sort_keys=True, separators=(",", ":"))

    def submit(self, architecture: dict[str, Any]) -> dict[str, Any]:
        key = self._key(architecture)
        with self._lock:
            for job in self._jobs.values():
                if job["key"] == key and job["status"] in ACTIVE:
                    return self._public(job)  # same design already in progress
            job = {"id": uuid.uuid4().hex, "key": key, "status": "queued", "created": time.time(),
                   "started": None, "finished": None, "plan_id": None, "verdict": None, "error": None,
                   "result": None}
            self._jobs[job["id"]] = job
            self._trim()
        self._pool.submit(self._work, job["id"], architecture)
        return self._public(job)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return self._public(job) if job else None

    def _work(self, job_id: str, architecture: dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job["status"], job["started"] = "running", time.time()
        try:
            cert = self._run(architecture)
        except Exception as exc:  # reported to the dashboard, never swallowed
            message = self._on_error(exc)
            log.warning("%s job %s failed: %s", self._name, job_id, message)
            with self._lock:
                job.update(status="error", error=message, finished=time.time())
            return
        with self._lock:
            if self._keep_result:
                job.update(status="done", result=cert, finished=time.time())
            else:
                job.update(status="done", plan_id=cert["plan_id"], verdict=cert["verdict"], finished=time.time())

    def _trim(self) -> None:
        done = [j for j in self._jobs.values() if j["status"] not in ACTIVE]
        for job in sorted(done, key=lambda j: j["created"])[: max(0, len(self._jobs) - MAX_JOBS)]:
            del self._jobs[job["id"]]

    def _public(self, job: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        position = None
        if job["status"] == "queued":
            position = sum(1 for j in self._jobs.values()
                           if j["status"] in ACTIVE and j["created"] < job["created"])
        end = job["finished"] or now
        public = {
            "job_id": job["id"], "status": job["status"], "plan_id": job["plan_id"], "verdict": job["verdict"],
            "error": job["error"], "queue_position": position,
            "elapsed_s": round(end - (job["started"] or job["created"]), 1),
        }
        if self._keep_result:
            public["result"] = job["result"]
        return public

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
