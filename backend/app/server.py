"""Start the GhostOps API:  python -m app.server [--host 127.0.0.1] [--port 8000]

Checks required settings first and exits with a clear message (no traceback)
if one is missing. Binds to 127.0.0.1 by default: this is a local tool.

Defaults come from the environment: GHOSTOPS_HOST (default 127.0.0.1) and PORT
(set by Render; default 8000). Binding anything other than loopback requires
GHOSTOPS_HOSTED=1, which turns on the API key check (see app/api.py).
"""

from __future__ import annotations

import argparse
import ipaddress
import sys

import uvicorn

from app.config import ConfigError, check_required, hosted, install_secret_filter, setting


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.server")
    parser.add_argument("--host", default=setting("GHOSTOPS_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(setting("PORT", "8000")))
    args = parser.parse_args(argv)
    try:
        check_required()
        if not is_loopback(args.host) and not hosted():
            raise ConfigError(
                f"GhostOps cannot start: refusing to listen on {args.host} without GHOSTOPS_HOSTED=1.\n"
                "Hosted mode requires GHOSTOPS_API_KEY for every POST/PUT/DELETE and disables "
                "plan_path/tf_dir. For local use, keep the default host 127.0.0.1."
            )
        from app.api import create_app

        app = create_app()  # opens the database: SQLite, or Postgres if GHOSTOPS_DATABASE_URL is set
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2

    print(f"GhostOps storage: {app.state.store.backend}", flush=True)  # never the URL
    config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
    install_secret_filter()  # after uvicorn has configured its log handlers
    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
