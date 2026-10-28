"""Internal, single-scan ZAP worker; never publish its port to the host."""
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

processes = {}
lock = threading.Lock()
slot = threading.BoundedSemaphore(1)


def validate(target):
    url = urlparse(target)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
        raise ValueError("Invalid target URL")
    records = socket.getaddrinfo(url.hostname, url.port or 443)
    if not records or any(not ipaddress.ip_address(r[4][0]).is_global for r in records):
        raise ValueError("Target must resolve to public IP addresses")


def kill(proc):
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.wait()


class Handler(BaseHTTPRequestHandler):
    def respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self.respond(200 if self.path == "/health" else 404, {"status": "ok"})

    def do_POST(self):
        if self.path.startswith("/cancel/"):
            with lock:
                proc = processes.get(self.path.rsplit("/", 1)[-1])
            if proc:
                kill(proc)
            self.respond(200, {"cancelled": proc is not None})
            return
        if self.path != "/scan":
            self.respond(404, {"detail": "Unknown route"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096:
                raise ValueError("Invalid request size")
            data = json.loads(self.rfile.read(length))
            job_id, target = data["id"], data["target"]
            if not re.fullmatch(r"[a-f0-9]{32}", job_id):
                raise ValueError("Invalid scan id")
            validate(target)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            self.respond(422, {"detail": str(exc)})
            return
        if not slot.acquire(blocking=False):
            self.respond(429, {"detail": "ZAP worker is busy; retry after its current scan"})
            return
        report = Path("/zap/wrk") / f"{job_id}.json"
        proc = None
        try:
            proc = subprocess.Popen(["zap-baseline.py", "-t", target, "-m", "1", "-T", "3", "-J", report.name, "-I"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            with lock:
                processes[job_id] = proc
            proc.wait(timeout=int(os.getenv("ZAP_SCAN_TIMEOUT", "240")))
            if proc.returncode not in (0, 1, 2) or not report.is_file():
                self.respond(502, {"detail": f"ZAP did not complete (exit {proc.returncode})"})
            else:
                self.respond(200, json.loads(report.read_text()))
        except subprocess.TimeoutExpired:
            self.respond(504, {"detail": "ZAP baseline timed out"})
        except Exception as exc:
            self.respond(502, {"detail": str(exc)})
        finally:
            if proc:
                kill(proc)
            with lock:
                processes.pop(job_id, None)
            report.unlink(missing_ok=True)
            slot.release()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
