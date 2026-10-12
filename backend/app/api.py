"""GhostOps HTTP API (FastAPI). Start it with:  python -m app.server

POST /analyze                         analyse a plan, store + return its certificate
     JSON  {"plan_path": "...", "tf_dir": "...", "use_groq": true}
           or {"plan": {...plan JSON...}, "tf_dir": ..., "use_groq": ...}
     multipart: file field "plan" (+ optional form fields tf_dir, use_groq)
     Without tf_dir no shadow run happens, so the verdict is BLOCKED (fail closed).
GET  /certificates                    summaries, newest first
GET  /certificates/{plan_id}          the certificate exactly as signed
GET  /certificates/{plan_id}/decisions   the audit log for that plan
POST /certificates/{plan_id}/decision {"decision": "approve"|"deny", "reviewer": "...", "comment": "..."}
     recorded in the append-only audit log; NEVER applied to any real system
GET  /verify/{plan_id}                re-check the stored certificate's signature (Ed25519 or HMAC)
GET  /public-key                      the Ed25519 public key that verifies certificates (404 if HMAC only)
GET  /demos, POST /analyze/demo/{bad|good}   run a bundled demo (no paths from the browser)
GET  /catalog                         services the Terraform generator supports, with form fields
POST /architectures/preview           {"services": [{"type", "config"}]} -> generated Terraform only
POST /architectures/check             same body -> static check for the builder (~20-30 s, no shadow,
                                      unsigned, not stored)
POST /architectures/analyze           same body (+ per-service "usage") -> generate, plan, full pipeline,
                                      stored certificate (?use_groq=false for template text)
GET  /comparisons                     compare slots A and B: both saved designs, diff, highlights
PUT  /comparisons/{A|B}               same body as /architectures/check: runs the static check
                                      and saves architecture + result snapshot in that slot
DELETE /comparisons/{A|B}             empty a slot
POST /architectures/certify           same body -> starts the full analysis as a background job (202)
GET  /jobs/{job_id}                   job status: queued | running | done (plan_id, verdict) | error
POST /architectures/advise            same body -> Trusted Advisor background job (202): every candidate
                                      change is planned, re-scored and priced (app/advisor.py)
GET  /architectures/advise/{job_id}   advisor job status; `result` holds the recommendations when done
GET  /health

CORS allows the dashboard at http://localhost:3000 plus any origins listed in
GHOSTOPS_CORS_ORIGINS (comma-separated). Request bodies and settings are never
logged; a log filter also redacts secret values if one slips through.

Hosted mode (GHOSTOPS_HOSTED=1, e.g. on Render): every POST/PUT/DELETE needs the
header X-GhostOps-Key equal to GHOSTOPS_API_KEY (401 otherwise), and /analyze
refuses plan_path and tf_dir (403): a caller must not name files on the server.
"""

from __future__ import annotations

import hmac
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Literal

from fastapi import FastAPI, HTTPException, Path as PathParam, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from app.advisor import advise
from app.architecture import analyze_architecture, check_architecture, services_with_resources
from app.catalog import catalog
from app.compare import comparison, snapshot
from app.jobs import JobManager
from app.shadow import ShadowError
from app.certificate import CertificateError, build_certificate, signature_alg, verify
from app.keys import configured_public_key, key_id, public_key_b64, public_key_pem
from app.generator import ArchitectureError, generate
from app.config import check_required, cors_origins, hosted, install_secret_filter, setting
from app.plan_parser import PlanParseError
from app.store import Store, open_store

log = logging.getLogger("ghostops.api")
API_KEY_HEADER = "X-GhostOps-Key"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HOSTED_PATHS_REFUSED = "plan_path and tf_dir are disabled on a hosted GhostOps; upload the plan JSON instead"
MAX_PLAN_BYTES = 20 * 1024 * 1024
PLAN_ID = PathParam(pattern=r"^[0-9a-f]{64}$", description="sha256 plan id")
NO_APPLY_NOTE = "Recorded in the audit log only. GhostOps never applies changes to any real system."
_ROOT = Path(__file__).resolve().parents[2]
DEMOS = {  # name -> (plan JSON, Terraform dir for the shadow run, description)
    "bad": (_ROOT / "backend" / "tests" / "fixtures" / "bad_plan.json", _ROOT / "demo" / "bad",
            "Open SSH, wildcard IAM policy, public S3 bucket, unencrypted RDS, EC2 behind the open group"),
    "good": (_ROOT / "backend" / "tests" / "fixtures" / "good_plan.json", _ROOT / "demo" / "good",
             "Tagged S3 bucket with a CloudWatch size alarm"),
}

Analyzer = Callable[..., dict[str, Any]]


class AnalyzeRequest(BaseModel):
    plan_path: str | None = None
    plan: dict[str, Any] | None = None
    tf_dir: str | None = None
    use_groq: bool = True


class DecisionRequest(BaseModel):
    decision: Literal["approve", "deny"]
    reviewer: str = Field(min_length=1, max_length=100, pattern=r"^[\w .@'-]+$")
    comment: str | None = Field(default=None, max_length=1000)


def _load_plan_file(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    if path.suffix.lower() != ".json" or not path.is_file():
        raise HTTPException(400, f"plan_path must be an existing .json file: {path_text}")
    if path.stat().st_size > MAX_PLAN_BYTES:
        raise HTTPException(413, "plan file is larger than 20 MB")
    return _decode_plan(path.read_bytes())


def _decode_plan(raw: bytes) -> dict[str, Any]:
    try:
        plan = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(422, f"plan is not valid JSON: {exc}") from None
    if not isinstance(plan, dict):
        raise HTTPException(422, "plan must be a JSON object (terraform show -json output)")
    return plan


def _refuse_server_paths(is_hosted: bool, *values: Any) -> None:
    if is_hosted and any(values):
        raise HTTPException(403, HOSTED_PATHS_REFUSED)


def _tf_dir(value: str | None) -> str | None:
    if not value:
        return None
    if not Path(value).is_dir():
        raise HTTPException(400, f"tf_dir must be an existing directory: {value}")
    return value


def create_app(store: Store | None = None, analyzer: Analyzer = build_certificate,
               architecture_analyzer: Callable[..., dict[str, Any]] = analyze_architecture,
               architecture_checker: Callable[..., dict[str, Any]] = check_architecture,
               architecture_advisor: Callable[..., dict[str, Any]] = advise) -> FastAPI:
    check_required()  # refuse to start without the signing secret

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        install_secret_filter()
        yield
        _app.state.jobs.shutdown()
        _app.state.advisor_jobs.shutdown()

    app = FastAPI(title="GhostOps", version="0.7.0", lifespan=lifespan)
    is_hosted = hosted()
    api_key = (setting("GHOSTOPS_API_KEY") or "").encode() if is_hosted else b""

    @app.middleware("http")
    async def require_api_key(request: Request, call_next):
        """Hosted mode: no POST/PUT/DELETE without the API key (constant-time compare)."""
        if is_hosted and request.method in MUTATING_METHODS:
            given = request.headers.get(API_KEY_HEADER, "").encode()
            if not hmac.compare_digest(given, api_key):
                return JSONResponse({"detail": f"missing or wrong {API_KEY_HEADER} header"}, status_code=401)
        return await call_next(request)

    # Added after the key check so CORS wraps it: a 401 still carries CORS headers.
    app.add_middleware(CORSMiddleware, allow_origins=cors_origins(), allow_methods=["GET", "POST", "PUT", "DELETE"],
                       allow_headers=["Content-Type", API_KEY_HEADER])
    app.state.store = store or open_store()

    def get_cert(plan_id: str) -> dict[str, Any]:
        cert = app.state.store.get_certificate(plan_id)
        if cert is None:
            raise HTTPException(404, f"no certificate for plan {plan_id}")
        return cert

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/analyze")
    async def analyze(request: Request) -> dict[str, Any]:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("multipart/form-data"):
            form = await request.form()
            upload = form.get("plan")
            if upload is None or not hasattr(upload, "read"):
                raise HTTPException(400, 'multipart upload needs a file field named "plan"')
            raw = await upload.read(MAX_PLAN_BYTES + 1)
            if len(raw) > MAX_PLAN_BYTES:
                raise HTTPException(413, "plan file is larger than 20 MB")
            plan = _decode_plan(raw)
            _refuse_server_paths(is_hosted, form.get("tf_dir"))
            tf_dir = _tf_dir(str(form.get("tf_dir") or "") or None)
            use_groq = str(form.get("use_groq", "true")).lower() not in ("false", "0", "no")
        else:
            try:
                body = AnalyzeRequest.model_validate(await request.json())
            except (ValueError, ValidationError) as exc:
                raise HTTPException(422, f"invalid request body: {exc}") from None
            if (body.plan_path is None) == (body.plan is None):
                raise HTTPException(422, "give exactly one of plan_path or plan")
            _refuse_server_paths(is_hosted, body.plan_path, body.tf_dir)
            plan = _load_plan_file(body.plan_path) if body.plan_path else body.plan
            tf_dir, use_groq = _tf_dir(body.tf_dir), body.use_groq

        try:
            cert = await run_in_threadpool(analyzer, plan, tf_dir, use_groq=use_groq)
        except PlanParseError as exc:
            raise HTTPException(422, f"not a usable Terraform plan: {exc}") from None
        except CertificateError as exc:
            raise HTTPException(500, str(exc)) from None
        app.state.store.save_certificate(cert)
        log.info("analyzed plan %s verdict=%s", cert["plan_id"], cert["verdict"])
        return cert

    @app.get("/catalog")
    def get_catalog() -> list[dict[str, Any]]:
        return catalog()

    @app.post("/architectures/preview")
    async def preview_architecture(request: Request) -> dict[str, Any]:
        """Terraform for an architecture. Generates only: no plan, no apply, nothing stored."""
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(422, "body must be JSON: {\"services\": [{\"type\": ..., \"config\": {...}}]}") from None
        try:
            generated = generate(body)
        except ArchitectureError as exc:
            raise HTTPException(422, {"message": "invalid architecture", "errors": exc.errors}) from None
        return {
            "terraform": generated.main_tf,
            "filename": "main.tf",
            "resources": generated.resources,
            "services": services_with_resources(generated),
        }

    @app.post("/architectures/check")
    async def check_architecture_endpoint(request: Request) -> dict[str, Any]:
        """Static check for the builder (plan, OPA, graph, cost, fixes; no shadow, not stored)."""
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(422, "body must be JSON") from None
        try:
            generate(body)
        except ArchitectureError as exc:
            raise HTTPException(422, {"message": "invalid architecture", "errors": exc.errors}) from None
        try:
            return await run_in_threadpool(architecture_checker, body)
        except ShadowError as exc:
            raise HTTPException(500, f"could not plan the generated Terraform: {exc}") from None

    def _certify(body: dict[str, Any]) -> dict[str, Any]:
        cert = architecture_analyzer(body, use_groq=True)
        app.state.store.save_certificate(cert)
        log.info("certified architecture plan %s verdict=%s", cert["plan_id"], cert["verdict"])
        return cert

    def _job_error(exc: Exception) -> str:
        if isinstance(exc, ShadowError):
            return f"could not plan the generated Terraform: {exc}"
        if isinstance(exc, CertificateError):
            return str(exc)
        log.exception("certify job crashed", exc_info=exc)
        return f"Certify failed unexpectedly ({type(exc).__name__}); see the API log."

    app.state.jobs = JobManager(_certify, _job_error)

    @app.post("/architectures/certify", status_code=202)
    async def certify_architecture(request: Request) -> dict[str, Any]:
        """Start a full analysis as a background job; poll GET /jobs/{job_id} for the result."""
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(422, "body must be JSON: {\"services\": [...]}") from None
        try:
            generate(body)  # invalid input is a 422 now, not a failed job later
        except ArchitectureError as exc:
            raise HTTPException(422, {"message": "invalid architecture", "errors": exc.errors}) from None
        return app.state.jobs.submit({"services": body["services"]})

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str = PathParam(pattern=r"^[0-9a-f]{32}$")) -> dict[str, Any]:
        job = app.state.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "unknown job (the API may have restarted; check the Certificates page)")
        return job

    def _advisor_error(exc: Exception) -> str:
        if isinstance(exc, ShadowError):
            return f"could not plan the generated Terraform: {exc}"
        log.exception("advisor job crashed", exc_info=exc)
        return f"The advisor failed unexpectedly ({type(exc).__name__}); see the API log."

    app.state.advisor_jobs = JobManager(architecture_advisor, _advisor_error, keep_result=True, name="advise")

    @app.post("/architectures/advise", status_code=202)
    async def advise_architecture(request: Request) -> dict[str, Any]:
        """Trusted Advisor: measure candidate changes as a background job (1-3 min);
        poll GET /architectures/advise/{job_id}, whose `result` holds the recommendations."""
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(422, "body must be JSON: {\"services\": [...]}") from None
        try:
            generate(body)
        except ArchitectureError as exc:
            raise HTTPException(422, {"message": "invalid architecture", "errors": exc.errors}) from None
        return app.state.advisor_jobs.submit({"services": body["services"]})

    @app.get("/architectures/advise/{job_id}")
    def get_advice(job_id: str = PathParam(pattern=r"^[0-9a-f]{32}$")) -> dict[str, Any]:
        job = app.state.advisor_jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "unknown advisor job (the API may have restarted); ask the advisor again")
        return job

    @app.post("/architectures/analyze")
    async def analyze_architecture_endpoint(request: Request, use_groq: bool = True) -> dict[str, Any]:
        """Generate Terraform for an architecture and run the full pipeline; returns the certificate."""
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(422, "body must be JSON: {\"services\": [{\"type\", \"config\", \"usage\"}]}") from None
        try:
            generate(body)  # validate first: a 422 must not wait for Terraform
        except ArchitectureError as exc:
            raise HTTPException(422, {"message": "invalid architecture", "errors": exc.errors}) from None
        try:
            cert = await run_in_threadpool(architecture_analyzer, body, use_groq=use_groq)
        except ShadowError as exc:
            raise HTTPException(500, f"could not plan the generated Terraform: {exc}") from None
        except CertificateError as exc:
            raise HTTPException(500, str(exc)) from None
        app.state.store.save_certificate(cert)
        log.info("analyzed architecture plan %s verdict=%s", cert["plan_id"], cert["verdict"])
        return cert

    @app.get("/comparisons")
    def get_comparisons() -> dict[str, Any]:
        return comparison(app.state.store.designs())

    @app.put("/comparisons/{slot}")
    async def save_comparison(request: Request, slot: Literal["A", "B"]) -> dict[str, Any]:
        """Save the current Builder design in slot A or B (runs the static check, ~30 s)."""
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(422, "body must be JSON") from None
        try:
            generate(body)
        except ArchitectureError as exc:
            raise HTTPException(422, {"message": "invalid architecture", "errors": exc.errors}) from None
        try:
            check = await run_in_threadpool(architecture_checker, body)
        except ShadowError as exc:
            raise HTTPException(500, f"could not plan the generated Terraform: {exc}") from None
        architecture = {"services": body["services"]}
        return app.state.store.save_design(slot, architecture, snapshot(check))

    @app.delete("/comparisons/{slot}")
    def delete_comparison(slot: Literal["A", "B"]) -> dict[str, Any]:
        if not app.state.store.delete_design(slot):
            raise HTTPException(404, f"slot {slot} is empty")
        return {"slot": slot, "deleted": True}

    @app.get("/demos")
    def list_demos() -> list[dict[str, str]]:
        return [{"name": name, "description": desc} for name, (_, _, desc) in DEMOS.items()]

    @app.post("/analyze/demo/{name}")
    async def analyze_demo(name: str, use_groq: bool = True) -> dict[str, Any]:
        """Run a bundled demo by name; the browser never sends file paths."""
        if name not in DEMOS:
            raise HTTPException(404, f"unknown demo {name!r}; choose one of {sorted(DEMOS)}")
        plan_file, tf_dir, _ = DEMOS[name]
        plan = _load_plan_file(str(plan_file))
        cert = await run_in_threadpool(analyzer, plan, str(tf_dir), use_groq=use_groq)
        app.state.store.save_certificate(cert)
        log.info("analyzed demo %s plan %s verdict=%s", name, cert["plan_id"], cert["verdict"])
        return cert

    @app.get("/certificates")
    def list_certificates() -> list[dict[str, Any]]:
        return app.state.store.list_certificates()

    @app.get("/certificates/{plan_id}")
    def get_certificate(plan_id: str = PLAN_ID) -> dict[str, Any]:
        return get_cert(plan_id)

    @app.get("/certificates/{plan_id}/decisions")
    def list_decisions(plan_id: str = PLAN_ID) -> list[dict[str, Any]]:
        get_cert(plan_id)
        return app.state.store.decisions(plan_id)

    @app.post("/certificates/{plan_id}/decision")
    def decide(body: DecisionRequest, plan_id: str = PLAN_ID) -> dict[str, Any]:
        cert = get_cert(plan_id)
        if cert["verdict"] != "BLOCKED_PENDING_REVIEW":
            raise HTTPException(409, "this certificate was auto-approved by policy; there is nothing to review")
        if not verify(cert):
            raise HTTPException(409, "stored certificate failed signature verification; refusing to record a decision")
        entry = app.state.store.add_decision(cert, body.decision, body.reviewer.strip(), body.comment)
        log.info("decision %s on plan %s by reviewer", body.decision, plan_id)
        return {**entry, "applied": False, "note": NO_APPLY_NOTE}

    @app.get("/verify/{plan_id}")
    def verify_certificate(plan_id: str = PLAN_ID) -> dict[str, Any]:
        cert = get_cert(plan_id)
        return {"plan_id": plan_id, "valid": verify(cert), "verdict": cert["verdict"],
                "timestamp": cert["timestamp"], "signature": cert["signature"],
                "signature_alg": signature_alg(cert)}

    @app.get("/public-key")
    def public_key() -> dict[str, str]:
        """Anyone can verify an Ed25519 certificate with this; only GhostOps can sign."""
        key = configured_public_key()
        if key is None:
            raise HTTPException(404, "this server signs with HMAC-SHA256 only (GHOSTOPS_SIGNING_KEY is not set)")
        return {"alg": "ed25519", "public_key": public_key_b64(key), "public_key_pem": public_key_pem(key),
                "key_id": key_id(key)}

    return app
