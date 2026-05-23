"""
Stdlib web frontend for the Secure P2P Messenger demo.

Run:
    python web_app.py
    python main.py web
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
import mimetypes
from pathlib import Path
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import webbrowser

from core.flow import SecureMessengerFlow


ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "frontend"

_session_lock = threading.RLock()
_session: SecureMessengerFlow | None = None
_configured_key_bits = 128


def _new_session(run_sample: bool = False) -> SecureMessengerFlow:
    session = SecureMessengerFlow(key_bits=_configured_key_bits)
    if run_sample:
        session.run_scripted_demo()
    return session


def _get_session() -> SecureMessengerFlow:
    global _session
    with _session_lock:
        if _session is None:
            _session = _new_session(run_sample=False)
        return _session


def _reset_session(run_sample: bool = False) -> SecureMessengerFlow:
    global _session
    with _session_lock:
        _session = _new_session(run_sample=run_sample)
        return _session


def _safe_static_path(request_path: str) -> Path | None:
    relative = "index.html" if request_path in ("", "/") else request_path.lstrip("/")
    candidate = (FRONTEND_DIR / relative).resolve()
    try:
        candidate.relative_to(FRONTEND_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


class SecureMessengerHandler(BaseHTTPRequestHandler):
    server_version = "SecureMessengerFrontend/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/state":
            self._send_json(_get_session().snapshot())
            return

        static_path = _safe_static_path(parsed.path)
        if static_path is None:
            self.send_error(404, "Not found")
            return

        content_type = mimetypes.guess_type(static_path.name)[0] or "application/octet-stream"
        content = static_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self._read_json_body()

            if parsed.path == "/api/demo":
                self._send_json(_reset_session(run_sample=True).snapshot())
                return

            if parsed.path == "/api/reset":
                run_sample = bool(body.get("runSample", False))
                self._send_json(_reset_session(run_sample=run_sample).snapshot())
                return

            if parsed.path == "/api/send":
                sender = str(body.get("from", "Alice"))
                message = str(body.get("message", "")).strip()
                if not message:
                    self._send_json({"error": "Message cannot be empty"}, status=400)
                    return
                with _session_lock:
                    session = _get_session()
                    event = session.send_message(sender, message)
                    payload = session.snapshot()
                    payload["last_event"] = event
                self._send_json(payload)
                return

            if parsed.path == "/api/revoke":
                peer = str(body.get("peer", "Alice"))
                with _session_lock:
                    session = _get_session()
                    status = session.revoke_certificate(peer)
                    payload = session.snapshot()
                    payload["revoked"] = status
                self._send_json(payload)
                return

            if parsed.path == "/api/simulation-demo":
                output = _run_simulation_capture()
                self._send_json({"ok": True, "output": output})
                return

            self.send_error(404, "Not found")
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # pragma: no cover - defensive HTTP boundary
            self._send_json({"error": f"Server error: {exc}"}, status=500)

    def log_message(self, format: str, *args) -> None:
        print(f"[frontend] {self.address_string()} - {format % args}")

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def _send_json(self, payload: dict, status: int = 200) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    key_bits: int = 128,
    open_browser: bool = True,
) -> None:
    global _configured_key_bits
    _configured_key_bits = key_bits
    FRONTEND_DIR.mkdir(exist_ok=True)

    server = ThreadingHTTPServer((host, port), SecureMessengerHandler)
    url = f"http://{host}:{port}"
    print(f"Secure Messenger frontend running at {url}")
    print("Press Ctrl+C to stop the server.")
    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping frontend server.")
    finally:
        server.server_close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp:
        temp.bind(("127.0.0.1", 0))
        return int(temp.getsockname()[1])


def _run_simulation_capture() -> str:
    from simulation.demo import run_full_simulation

    buffer = io.StringIO()
    ca_port = _free_port()
    relay_port = _free_port()
    with redirect_stdout(buffer):
        run_full_simulation(
            ca_port=ca_port,
            relay_port=relay_port,
            key_bits=64,
        )
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the Secure Messenger web frontend.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--key-bits", type=int, default=128)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    run_server(
        host=args.host,
        port=args.port,
        key_bits=args.key_bits,
        open_browser=not args.no_browser,
    )


if __name__ == "__main__":
    main()
