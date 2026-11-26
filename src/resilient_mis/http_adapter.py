"""Optional local HTTP adapter. It only translates requests into the SAME ``MisService`` calls the CLI uses.

Binds to 127.0.0.1 by default, has no TLS and is not meant to be exposed: it exists to show the service functions behind a
second interface. Denied and missing records both return 404 with the same body.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from resilient_mis.errors import AccessDenied, ConcurrencyError, IdempotencyConflict, StoreUnavailable, ValidationError
from resilient_mis.service import MisService

MAX_BODY = 64 * 1024


def make_handler(svc: MisService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "resilient-mis"

        def log_message(self, fmt: str, *args: Any) -> None:  # no request logging: URLs and tokens never reach logs
            return

        def _send(self, code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _token(self) -> str:
            h = self.headers.get("Authorization", "")
            return h[7:] if h.startswith("Bearer ") else ""

        def _guard(self, fn) -> None:
            try:
                code, body = fn()
                self._send(code, body)
            except AccessDenied:
                self._send(404, {"error": "access denied or record not available"})
            except ValidationError as exc:
                self._send(400, {"error": str(exc)})
            except (ConcurrencyError, IdempotencyConflict) as exc:
                self._send(409, {"error": str(exc)})
            except StoreUnavailable:
                self._send(503, {"error": "service unavailable"})

        def do_GET(self) -> None:  # noqa: N802
            parts = [p for p in self.path.split("?")[0].split("/") if p]

            def run() -> tuple[int, dict[str, Any]]:
                if parts == ["health"]:
                    return 200, svc.health()
                if len(parts) == 3 and parts[0] == "orders":
                    return 200, asdict(svc.read_order(self._token(), parts[1], parts[2]))
                if len(parts) == 3 and parts[0] == "reports":
                    rep = svc.spending_report(self._token(), parts[1], parts[2])
                    return 200, {**rep.to_dict(), "digest": rep.digest()}
                return 404, {"error": "not found"}

            self._guard(run)

        def do_POST(self) -> None:  # noqa: N802
            def run() -> tuple[int, dict[str, Any]]:
                n = int(self.headers.get("Content-Length", "0"))
                if n > MAX_BODY:
                    raise ValidationError("request body too large")
                try:
                    b = json.loads(self.rfile.read(n) or b"{}")
                except ValueError as exc:
                    raise ValidationError("body is not valid JSON") from exc
                if self.path == "/orders":
                    r = svc.create_order(self._token(), b.get("tenant", ""), b.get("record_id", ""), b.get("department", ""), b.get("vendor", ""),
                                         b.get("currency", ""), b.get("amount_minor"), b.get("status", "draft"), b.get("idempotency_key"))
                    return 201, asdict(r)
                if self.path == "/orders/update":
                    r = svc.update_order(self._token(), b.get("tenant", ""), b.get("record_id", ""), b.get("changes") or {}, int(b.get("expected_version", 0)),
                                         b.get("idempotency_key"))
                    return 200, asdict(r)
                return 404, {"error": "not found"}

            self._guard(run)

    return Handler


def serve(svc: MisService, host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(svc))
    print(f"serving on http://{host}:{port} (local only; Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
