"""GhostOps gate as an MCP server (stdio), so an AI coding agent can be told to check
every Terraform plan before it applies anything.

  python -m app.mcp_gate

Tools
  ghostops_check_plan(plan_json_path, tf_dir)  certify a `terraform show -json` plan
  ghostops_get_certificate(plan_id)            re-read a certificate and its review state

Both return the verdict, the blocking findings, the certificate id and `apply_allowed`:
true only for AUTO_APPROVED, or for BLOCKED_PENDING_REVIEW that a human approved in the
dashboard. The agent must not run `terraform apply` otherwise. Certificates come from the
local API (GHOSTOPS_API_URL, default http://127.0.0.1:8000) if it is running, else from the
same pipeline and database in this process.

The protocol is newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio transport);
stdout carries protocol messages only, diagnostics go to stderr.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, TextIO

from app import gate

SERVER_INFO = {"name": "ghostops-gate", "version": "0.7.0"}
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
INSTRUCTIONS = (
    "Before any `terraform apply`, run `terraform plan -out tf.plan` and "
    "`terraform show -json tf.plan > plan.json`, then call ghostops_check_plan. Apply only that "
    "saved plan, and only if apply_allowed is true. If the verdict is BLOCKED_PENDING_REVIEW, stop "
    "and give the user the dashboard_url; after a human approves it there, call "
    "ghostops_get_certificate with the certificate_id to confirm before applying."
)

TOOLS = [
    {
        "name": "ghostops_check_plan",
        "description": (
            "Risk-check a Terraform plan with GhostOps (OPA policy, blast radius, MiniStack shadow apply, "
            "cost) and return the signed certificate's verdict, blocking findings and certificate_id. "
            "Call this before every terraform apply; apply only if apply_allowed is true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "plan_json_path": {"type": "string", "description": "Path to `terraform show -json` output of a saved plan"},
                "tf_dir": {"type": "string", "description": "The Terraform directory the plan came from (for the shadow run)"},
            },
            "required": ["plan_json_path", "tf_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ghostops_get_certificate",
        "description": (
            "Read a GhostOps certificate by its id (plan sha256) with its current review state. "
            "Use it after a human reviewed a blocked plan: apply_allowed becomes true only on an approve decision."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"plan_id": {"type": "string", "description": "certificate_id from ghostops_check_plan"}},
            "required": ["plan_id"],
            "additionalProperties": False,
        },
    },
]


class GateServer:
    def __init__(self, client_factory: Callable[[], Any] = gate.default_client):
        self._client_factory = client_factory
        self._client: Any = None

    def client(self) -> Any:
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    # Tool functions (also the unit-tested surface).
    def ghostops_check_plan(self, plan_json_path: str, tf_dir: str) -> dict[str, Any]:
        return gate.check_plan(self.client(), plan_json_path, tf_dir)

    def ghostops_get_certificate(self, plan_id: str) -> dict[str, Any]:
        return gate.get_certificate(self.client(), plan_id)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tools = {"ghostops_check_plan": self.ghostops_check_plan, "ghostops_get_certificate": self.ghostops_get_certificate}
        if name not in tools:
            return _tool_error(f"unknown tool {name!r}")
        try:
            result = tools[name](**arguments)
        except TypeError as exc:
            return _tool_error(f"bad arguments for {name}: {exc}")
        except Exception as exc:  # fail closed: an error is never an approval
            return _tool_error(f"{type(exc).__name__}: {exc}. Do NOT apply: no valid GhostOps approval.")
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "structuredContent": result, "isError": False}

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """One JSON-RPC message in, the response out (None for notifications)."""
        method, msg_id = message.get("method"), message.get("id")
        if msg_id is None:
            return None  # notifications (initialized, cancelled) need no answer
        params = message.get("params") or {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            result = {
                "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": INSTRUCTIONS,
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = self.call_tool(str(params.get("name")), params.get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def serve(self, stdin: TextIO, stdout: TextIO) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("not a JSON object")
            except ValueError as exc:
                response: dict[str, Any] | None = {"jsonrpc": "2.0", "id": None,
                                                   "error": {"code": -32700, "message": f"parse error: {exc}"}}
            else:
                response = self.handle(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()


def _tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def main() -> None:
    stdin = open(sys.stdin.fileno(), encoding="utf-8", closefd=False)
    stdout = open(sys.stdout.fileno(), "w", encoding="utf-8", newline="\n", closefd=False)
    GateServer().serve(stdin, stdout)


if __name__ == "__main__":
    main()
