"""Loopback-only HTTP UI bridge for one real TLS + Reliable UDP client.

The HTTP request threads never touch UDP sockets. Commands are dispatched to
one application worker and inbound events are consumed by a separate worker.
No new network protocol is implemented here: CollaborationClient owns TLS,
REGISTER, AES-GCM and B's reliable transport.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import os
import shutil
import tempfile
from urllib.parse import quote, unquote
from pathlib import Path
import queue
import secrets
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from client.core.session import CollaborationClient
from common.models import (
    ApplicationValidationError,
    validate_chat_text,
    validate_chat_username,
)

UI_DIR = Path(__file__).resolve().parents[1] / "ui"
MAX_REQUEST_BYTES = 16_384
MAX_HISTORY = 256
from common.constants import MAX_FILE_SIZE as MAX_GUI_FILE_BYTES

TRANSFER_ID_RE = re.compile(r"[0-9a-f]{32}\Z")


def _safe_file_name(name: str) -> str:
    """Reject paths and OS-special names; never use a browser path directly."""
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 200
        or name in (".", "..")
        or name[-1:] in (" ", ".")
        or any(ch in name for ch in '/\\\0\r\n<>:"|?*')
        or any(ord(ch) < 32 for ch in name)
    ):
        raise ValueError("Invalid file name")
    stem = name.split(".", 1)[0].upper()
    if stem in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        raise ValueError("Reserved file name")
    return name


@dataclass
class _Command:
    kind: str
    args: tuple[Any, ...] = ()
    done: threading.Event = field(default_factory=threading.Event)
    status: int = 500
    payload: dict[str, Any] = field(default_factory=dict)


class LocalGUIBridge:
    """One local-browser session, one registered remote UDP client.

    Browser HTTP is *always* bound to 127.0.0.1, including when the real UDP
    server lives on a LAN address. One bridge process = one authenticated user.
    Use distinct local ports for two browser users on the same computer.
    """

    def __init__(
        self,
        *,
        port: int = 8000,
        server_host: str = "127.0.0.1",
        tcp_port: int = 9000,
        trusted_cert: Path | None = None,
        client_factory: Callable[..., CollaborationClient] = CollaborationClient,
    ):
        self.server_host = server_host
        self.tcp_port = tcp_port
        self.trusted_cert = trusted_cert
        self._client_factory = client_factory
        self._lock = threading.RLock()
        self._client: CollaborationClient | None = None
        self._state = "disconnected"
        self._username: str | None = None
        self._users: set[str] = set()
        self._last_error: str | None = None
        self._history: deque[dict[str, Any]] = deque(maxlen=MAX_HISTORY)
        self._cursor = 0
        self._token = secrets.token_urlsafe(32)
        self._jobs: queue.Queue[_Command | None] = queue.Queue(maxsize=32)
        self._file_area = tempfile.TemporaryDirectory(prefix="collab-gui-files-")
        self._file_requests: dict[int, dict[str, Any]] = {}
        self._file_transfers: dict[str, dict[str, Any]] = {}
        self._stopping = threading.Event()
        self._is_serving = threading.Event()
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "NetworkCollabLocalUI/1.0"
            sys_version = ""

            def log_message(self, *args) -> None:
                # Avoid logging credentials, local paths or sensitive events.
                return

            def _headers(self, status: int, mime: str, length: int) -> None:
                self.send_response(status)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; "
                    "script-src 'self'; style-src 'self'; connect-src 'self'; "
                    "img-src 'self' data:; object-src 'none'; "
                    "base-uri 'none'; frame-ancestors 'none'",
                )
                self.end_headers()

            def _write(self, status: int, data: bytes, mime: str) -> None:
                self._headers(status, mime, len(data))
                self.wfile.write(data)

            def _json(self, status: int, obj: dict) -> None:
                self._write(
                    status,
                    json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8",
                )

            def _check_host(self) -> bool:
                host = (self.headers.get("Host") or "").lower().strip()
                port_string = str(bridge.port)
                if host not in (f"127.0.0.1:{port_string}", f"localhost:{port_string}"):
                    self._json(403, {"error": "Only localhost requests are allowed"})
                    return False
                return True

            def _check_post(self, *, binary: bool = False) -> bool:
                if not self._check_host():
                    return False
                if self.headers.get("X-Bridge-Token") != bridge._token:
                    self._json(403, {"error": "Invalid bridge token"})
                    return False
                origin = self.headers.get("Origin")
                if origin is not None:
                    try:
                        parsed = urlsplit(origin)
                        valid = (
                            parsed.scheme == "http"
                            and parsed.hostname in ("127.0.0.1", "localhost")
                            and parsed.port == bridge.port
                            and not parsed.username
                            and not parsed.password
                        )
                    except ValueError:
                        valid = False
                    if not valid:
                        self._json(403, {"error": "Invalid request origin"})
                        return False
                if self.headers.get("Transfer-Encoding"):
                    self._json(
                        400, {"error": "Chunked request bodies are not supported"}
                    )
                    return False
                expected = "application/octet-stream" if binary else "application/json"
                if (
                    self.headers.get("Content-Type", "")
                    .split(";", 1)[0]
                    .strip()
                    .lower()
                    != expected
                ):
                    self._json(415, {"error": f"Expected {expected}"})
                    return False
                return True

            def do_GET(self) -> None:
                if not self._check_host():
                    return
                path = urlsplit(self.path)
                if path.path == "/api/status":
                    self._json(200, {**bridge.status(), "bridge_token": bridge._token})
                elif path.path.startswith("/api/file/download/"):
                    if self.headers.get("X-Bridge-Token") != bridge._token:
                        self._json(403, {"error": "Invalid bridge token"})
                        return
                    tid = path.path.removeprefix("/api/file/download/")
                    status, payload, name = bridge.download_file(tid)
                    if status != 200:
                        self._json(
                            status, {"error": "File is not available for download"}
                        )
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header(
                        "Content-Length", str(os.fstat(payload.fileno()).st_size)
                    )
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header(
                        "Content-Disposition",
                        "attachment; filename=\"download.bin\"; filename*=UTF-8''"
                        + quote(name),
                    )
                    self.end_headers()
                    with payload:
                        shutil.copyfileobj(payload, self.wfile, 128 * 1024)
                elif path.path == "/api/events":
                    try:
                        value = parse_qs(path.query).get("since", ["0"])[0]
                        since = int(value)
                        if since < 0:
                            raise ValueError
                    except (ValueError, OverflowError):
                        self._json(400, {"error": "Invalid event cursor"})
                        return
                    self._json(200, bridge.events_since(since))
                else:
                    paths = {
                        "/": ("index.html", "text/html; charset=utf-8"),
                        "/index.html": ("index.html", "text/html; charset=utf-8"),
                        "/style.css": ("style.css", "text/css; charset=utf-8"),
                        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                    }
                    asset = paths.get(path.path)
                    if asset is None:
                        self._json(404, {"error": "Not found"})
                        return
                    name, mime = asset
                    self._write(200, (UI_DIR / name).read_bytes(), mime)

            def do_POST(self) -> None:
                path = urlsplit(self.path).path
                binary = path == "/api/file/offer"
                if not self._check_post(binary=binary):
                    return
                try:
                    content_length = int(self.headers.get("Content-Length", ""))
                    limit = MAX_GUI_FILE_BYTES if binary else MAX_REQUEST_BYTES
                    if not 1 <= content_length <= limit:
                        raise ValueError
                    if binary:
                        filename = _safe_file_name(
                            unquote(
                                self.headers.get("X-File-Name", ""), errors="strict"
                            )
                        )
                        recipient = validate_chat_username(
                            self.headers.get("X-Recipient", "")
                        )
                        upload = tempfile.TemporaryFile()
                        try:
                            remaining = content_length
                            while remaining:
                                block = self.rfile.read(min(128 * 1024, remaining))
                                if not block:
                                    raise ValueError("Incomplete upload")
                                upload.write(block)
                                remaining -= len(block)
                            upload.seek(0)
                            command = _Command(
                                "file_offer",
                                (recipient, filename, upload, content_length),
                            )
                        except BaseException:
                            upload.close()
                            raise
                    else:
                        payload = json.loads(self.rfile.read(content_length))
                        if not isinstance(payload, dict):
                            raise ValueError
                except (
                    ValueError,
                    UnicodeError,
                    ApplicationValidationError,
                    json.JSONDecodeError,
                ):
                    self._json(
                        400, {"error": "Invalid upload, file name, or request size"}
                    )
                    return
                if binary:
                    pass
                elif path == "/api/login":
                    username = payload.get("username")
                    password = payload.get("password")
                    if (
                        not isinstance(username, str)
                        or not 1 <= len(username) <= 128
                        or not isinstance(password, str)
                        or not 1 <= len(password) <= 1024
                    ):
                        self._json(400, {"error": "Invalid username or password"})
                        return
                    command = _Command("login", (username, password))
                elif path == "/api/logout":
                    command = _Command("logout")
                elif path in ("/api/file/accept", "/api/file/reject"):
                    tid = payload.get("transfer_id")
                    if (
                        set(payload) != {"transfer_id"}
                        or not isinstance(tid, str)
                        or not TRANSFER_ID_RE.fullmatch(tid)
                    ):
                        self._json(400, {"error": "Invalid transfer ID"})
                        return
                    command = _Command(
                        "file_accept" if path.endswith("accept") else "file_reject",
                        (tid,),
                    )
                elif path in ("/api/chat/direct", "/api/chat/broadcast"):
                    mode = "direct" if path.endswith("direct") else "broadcast"
                    wanted = {"to", "text"} if mode == "direct" else {"text"}
                    if set(payload) != wanted:
                        self._json(400, {"error": "Invalid chat request fields"})
                        return
                    try:
                        text = validate_chat_text(payload["text"])
                        if mode == "direct":
                            target = validate_chat_username(payload["to"])
                    except (ApplicationValidationError, UnicodeError):
                        self._json(
                            400,
                            {
                                "error": "Invalid chat text (maximum 1000 UTF-8 bytes) or recipient"
                            },
                        )
                        return
                    command = _Command(
                        mode, (target, text) if mode == "direct" else (text,)
                    )
                else:
                    self._json(404, {"error": "Not found"})
                    return
                try:
                    bridge._jobs.put_nowait(command)
                except queue.Full:
                    if binary:
                        upload.close()
                    self._json(503, {"error": "Bridge command queue full"})
                    return
                if not command.done.wait(timeout=25):
                    self._json(504, {"error": "Application command timed out"})
                    return
                self._json(command.status, command.payload)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self._worker = threading.Thread(
            target=self._commands_loop, name="gui-commands", daemon=True
        )
        self._reader = threading.Thread(
            target=self._events_loop, name="gui-events", daemon=True
        )
        self._worker.start()
        self._reader.start()

    def _push(
        self,
        kind: str,
        body: dict[str, Any],
        *,
        reply_to: int | None = None,
        message_id: int | None = None,
    ) -> None:
        with self._lock:
            self._cursor += 1
            item = {
                "seq": self._cursor,
                "type": kind,
                "body": body,
                "ts": int(time.time() * 1000),
            }
            if reply_to is not None:
                item["reply_to"] = reply_to
            if message_id is not None:
                item["message_id"] = message_id
            self._history.append(item)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state,
                "username": self._username,
                "users": sorted(self._users, key=str.casefold),
                "error": self._last_error,
                "cursor": self._cursor,
                "server_host": self.server_host,
                "tcp_port": self.tcp_port,
                "transfers": self._public_transfers(),
            }

    def events_since(self, since: int) -> dict[str, Any]:
        with self._lock:
            first = self._history[0]["seq"] if self._history else self._cursor + 1
            events = [x for x in self._history if x["seq"] > since][:100]
            cursor = events[-1]["seq"] if events else max(since, self._cursor)
            return {
                "events": events,
                "cursor": cursor,
                "gap": since < first - 1,
                "state": self._state,
                "username": self._username,
                "users": sorted(self._users, key=str.casefold),
                "error": self._last_error,
                "transfers": self._public_transfers(),
            }

    def _public_transfers(self) -> list[dict]:
        return [
            {k: v for k, v in item.items() if k not in ("_path", "_stage")}
            for item in self._file_transfers.values()
        ]

    def download_file(self, tid: str) -> tuple[int, bytes, str]:
        if not TRANSFER_ID_RE.fullmatch(tid):
            return 404, b"", ""
        with self._lock:
            item = self._file_transfers.get(tid)
            if (
                self._state != "online"
                or item is None
                or item.get("role") != "receiver"
                or item.get("status") != "COMPLETED"
            ):
                return 404, b"", ""
            path = item.get("_path")
            if path is None:
                return 404, b"", ""
            try:
                data = Path(path).open("rb")
            except OSError:
                return 404, b"", ""
            if os.fstat(data.fileno()).st_size != item["size"]:
                data.close()
                return 404, b"", ""
            return 200, data, item["filename"]

    def _reset_files(self) -> None:
        # Caller holds the bridge lock. Close the old client before cleanup.
        self._file_requests.clear()
        self._file_transfers.clear()
        self._file_area.cleanup()
        self._file_area = tempfile.TemporaryDirectory(prefix="collab-gui-files-")

    def _send_file_offer(
        self, recipient: str, filename: str, upload, size: int
    ) -> tuple[int, dict]:
        with upload, self._lock:
            cli = self._client
            if self._state != "online" or cli is None:
                return 409, {"error": "Login required"}
            if cli.failure is not None:
                return 502, {"error": "UDP connection failed"}
            if recipient == self._username or recipient not in self._users:
                return 409, {"error": "Recipient is not online"}
            if not 1 <= size <= MAX_GUI_FILE_BYTES:
                return 400, {"error": "File must be 1 byte to 50 MiB"}
            stage = Path(self._file_area.name) / "outgoing" / secrets.token_hex(8)
            stage.mkdir(parents=True, exist_ok=False)
            path = stage / filename
            try:
                with path.open("xb") as output:
                    shutil.copyfileobj(upload, output, 128 * 1024)
                reqid = cli.offer_file(recipient, path)
            except (OSError, ValueError, RuntimeError) as exc:
                path.unlink(missing_ok=True)
                try:
                    stage.rmdir()
                except OSError:
                    pass
                return 409, {"error": f"Cannot offer file ({type(exc).__name__})"}
            self._file_requests[reqid] = {
                "filename": filename,
                "size": size,
                "peer": recipient,
                "_stage": path,
            }
            self._push(
                "FILE_QUEUED",
                {
                    "request_id": reqid,
                    "filename": filename,
                    "size": size,
                    "to": recipient,
                },
            )
            return 202, {"ok": True, "request_id": reqid}

    def _answer_file_offer(self, tid: str, *, accept: bool) -> tuple[int, dict]:
        with self._lock:
            cli = self._client
            item = self._file_transfers.get(tid)
            if self._state != "online" or cli is None:
                return 409, {"error": "Login required"}
            if (
                not item
                or item.get("role") != "receiver"
                or item.get("status") != "offered"
            ):
                return 409, {"error": "File offer is not pending"}
            try:
                if accept:
                    target_dir = Path(self._file_area.name) / "downloads" / tid
                    target_dir.mkdir(parents=True, exist_ok=False)
                    destination = target_dir / item["filename"]
                    request_id = cli.accept_file(tid, destination)
                    item["_path"] = destination
                    item["status"] = "accepting"
                else:
                    request_id = cli.reject_file(tid)
                    item["status"] = "rejecting"
            except (ValueError, OSError, RuntimeError) as exc:
                return 409, {
                    "error": f"Cannot respond to file offer ({type(exc).__name__})"
                }
            return 202, {"ok": True, "request_id": request_id}

    def _track_file_event(self, kind: str, body: dict, reply_to: int | None) -> dict:
        """Update metadata only; never fabricate transport progress."""
        body = dict(body)
        tid = body.get("transfer_id")
        if kind == "FILE_OFFER_ACK" and isinstance(tid, str):
            pending = self._file_requests.pop(reply_to, None)
            if pending:
                self._file_transfers[tid] = {
                    "transfer_id": tid,
                    "filename": pending["filename"],
                    "size": pending["size"],
                    "peer": pending["peer"],
                    "role": "sender",
                    "status": "offered",
                    "bytes_received": 0,
                    "confirmed_bytes": 0,
                    "_stage": pending["_stage"],
                }
                body.update(
                    filename=pending["filename"],
                    size=pending["size"],
                    to=pending["peer"],
                )
        elif kind == "FILE_OFFER" and isinstance(tid, str):
            try:
                name = _safe_file_name(body.get("filename"))
                size = body.get("size")
                if type(size) is not int or not 1 <= size <= MAX_GUI_FILE_BYTES:
                    raise ValueError
            except ValueError:
                return body
            self._file_transfers[tid] = {
                "transfer_id": tid,
                "filename": name,
                "size": size,
                "peer": body.get("from"),
                "role": "receiver",
                "status": "offered",
                "bytes_received": 0,
            }
        elif isinstance(tid, str) and tid in self._file_transfers:
            item = self._file_transfers[tid]
            if kind == "FILE_START":
                item["status"] = "transferring"
            elif kind == "FILE_PROGRESS" and item["role"] == "receiver":
                received = body.get("received_bytes")
                if (
                    type(received) is int
                    and item["bytes_received"] <= received <= item["size"]
                ):
                    item["bytes_received"] = received
            elif kind == "FILE_PROGRESS" and item["role"] == "sender":
                confirmed = body.get("confirmed_bytes")
                if (
                    body.get("role") == "sender"
                    and type(confirmed) is int
                    and item["confirmed_bytes"] <= confirmed <= item["size"]
                ):
                    item["confirmed_bytes"] = confirmed
            elif kind == "FILE_RESULT":
                item["status"] = body.get("status", "FAILED")
                if item["status"] == "COMPLETED":
                    if item["role"] == "sender":
                        item["confirmed_bytes"] = item["size"]
                    else:
                        item["bytes_received"] = item["size"]
                if item["role"] == "sender":
                    stage = item.pop("_stage", None)
                    if stage:
                        Path(stage).unlink(missing_ok=True)
                elif item["status"] == "COMPLETED":
                    path = item.get("_path")
                    if not path or not Path(path).is_file():
                        item["status"] = "FAILED"
        return body

    def _login(self, username: str, password: str) -> tuple[int, dict]:
        with self._lock:
            if self._state not in ("disconnected", "error") or self._client is not None:
                return 409, {"error": "A client is already connected"}
            self._state = "connecting"
            self._last_error = None
            # Never expose a previous account's chat history to the next login.
            self._history.clear()
        cli = None
        try:
            cli = self._client_factory(
                host=self.server_host,
                tcp_port=self.tcp_port,
                trusted_cert=self.trusted_cert,
            )
            cli.connect()
            accepted = cli.authenticate(username, password, timeout_s=8)
            if not accepted:
                cli.close()
                with self._lock:
                    self._state = "disconnected"
                    self._last_error = "Sai tên đăng nhập hoặc mật khẩu"
                    self._push("AUTH_FAIL", {"code": "AUTH_FAILED"})
                return 401, {"error": "Sai tên đăng nhập hoặc mật khẩu"}
            with self._lock:
                self._client = cli
                self._username = username
                self._users = {username}
                self._state = "online"
                self._push("BRIDGE_ONLINE", {"username": username})
            return 200, {"ok": True, **self.status()}
        except Exception as exc:
            if cli is not None:
                cli.close()
            with self._lock:
                self._state = "disconnected"
                self._last_error = f"Không kết nối được máy chủ ({type(exc).__name__})"
            return 502, {"error": self._last_error}

    def _logout(self) -> tuple[int, dict]:
        with self._lock:
            cli = self._client
            self._client = None
            self._state = "disconnected"
            self._username = None
            self._users.clear()
            self._last_error = None
            self._history.clear()
            self._push("BRIDGE_OFFLINE", {})
        if cli is not None:
            cli.close()
        with self._lock:
            self._reset_files()
        return 200, {"ok": True, **self.status()}

    def _send_chat(self, kind: str, *args: str) -> tuple[int, dict]:
        """Queue chat on the existing encrypted reliable stream 1.

        An HTTP 202 means only local transport queue acceptance. The browser
        must await CHAT_ACCEPTED for server-side queue confirmation; it is not
        proof of delivery to or reading by the recipient.
        """
        with self._lock:
            cli = self._client
            if self._state != "online" or cli is None:
                return 409, {"error": "Please authenticate before sending chat"}
        try:
            if cli.failure is not None:
                return 502, {"error": "UDP connection is no longer available"}
            message_id = (
                cli.send_direct(args[0], args[1])
                if kind == "direct"
                else cli.send_broadcast(args[0])
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return 502, {"error": f"Could not enqueue chat ({type(exc).__name__})"}
        return 202, {
            "ok": True,
            "queued": True,
            "scope": kind,
            "request_id": message_id,
        }

    def _commands_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                command = self._jobs.get(timeout=0.1)
            except queue.Empty:
                continue
            if command is None:
                break
            try:
                if command.kind == "login":
                    command.status, command.payload = self._login(*command.args)
                elif command.kind == "logout":
                    command.status, command.payload = self._logout()
                elif command.kind in ("direct", "broadcast"):
                    command.status, command.payload = self._send_chat(
                        command.kind, *command.args
                    )
                elif command.kind == "file_offer":
                    command.status, command.payload = self._send_file_offer(
                        *command.args
                    )
                elif command.kind in ("file_accept", "file_reject"):
                    command.status, command.payload = self._answer_file_offer(
                        command.args[0], accept=command.kind == "file_accept"
                    )
                else:
                    command.status, command.payload = 400, {"error": "Unknown command"}
            except Exception:
                command.status, command.payload = 500, {
                    "error": "Internal bridge error"
                }
            finally:
                command.done.set()

    def _on_transport_failure(self, cli: CollaborationClient) -> None:
        """Fail closed once; never reconnect or replay app actions automatically.

        Keep the old client attached while closing so a concurrent /api/login
        cannot start another account before the old client's file handles and
        receive thread are released (important for TemporaryDirectory on Windows).
        """
        with self._lock:
            if self._client is not cli or self._state != "online":
                return
            self._state = "disconnecting"
        try:
            cli.close()
        except Exception:
            # Preserve fail-closed state even if transport shutdown raises.
            pass
        with self._lock:
            if self._client is not cli:
                return  # A concurrent explicit logout already owns cleanup.
            self._client = None
            self._state = "error"
            self._username = None
            self._users.clear()
            self._last_error = (
                "Kết nối với server đã bị gián đoạn. "
                "Hãy đăng nhập lại; các thao tác chưa được xác nhận có thể chưa hoàn tất."
            )
            self._history.clear()
            self._reset_files()
            self._push(
                "BRIDGE_ERROR", {"code": "TRANSPORT_ERROR", "retry": "LOGIN_AGAIN"}
            )

    def _events_loop(self) -> None:
        while not self._stopping.is_set():
            with self._lock:
                cli = self._client
            if cli is None:
                self._stopping.wait(0.1)
                continue
            # Never forward queued application events after transport failure.
            if cli.failure is not None:
                self._on_transport_failure(cli)
                continue
            try:
                event = cli.receive_event(timeout_s=0.12)
            except queue.Empty:
                if cli.failure is not None:
                    self._on_transport_failure(cli)
                continue
            if cli.failure is not None:
                self._on_transport_failure(cli)
                continue
            with self._lock:
                if self._client is not cli or self._state != "online":
                    continue
                kind = event.get("type")
                body = event.get("body")
                if not isinstance(body, dict):
                    body = {}
                if kind == "USER_LIST" and isinstance(body.get("users"), list):
                    self._users = {u for u in body["users"] if isinstance(u, str)}
                elif kind == "PRESENCE":
                    user = body.get("username")
                    if isinstance(user, str):
                        if body.get("status") == "online":
                            self._users.add(user)
                        elif body.get("status") == "offline":
                            self._users.discard(user)
                if kind == "ERROR" and body.get("message") == "FILE_OFFER":
                    reqid = event.get("reply_to")
                    pending = self._file_requests.pop(reqid, None)
                    if pending:
                        stage = pending.get("_stage")
                        if stage:
                            Path(stage).unlink(missing_ok=True)
                        self._push(
                            "FILE_OFFER_REJECTED",
                            {"request_id": reqid, "code": body.get("code", "ERROR")},
                        )
                if isinstance(kind, str) and kind.startswith("FILE_"):
                    body = self._track_file_event(kind, body, event.get("reply_to"))
                self._push(
                    str(kind),
                    body,
                    reply_to=event.get("reply_to"),
                    message_id=event.get("id"),
                )

    def serve_forever(self) -> None:
        self._is_serving.set()
        try:
            self.httpd.serve_forever(poll_interval=0.1)
        finally:
            self._is_serving.clear()
            self.close()

    def close(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        if self._is_serving.is_set():
            self.httpd.shutdown()
        self.httpd.server_close()
        with self._lock:
            cli = self._client
            self._client = None
        if cli is not None:
            cli.close()
        with self._lock:
            self._file_requests.clear()
            self._file_transfers.clear()
            self._file_area.cleanup()
        try:
            self._jobs.put_nowait(None)
        except queue.Full:
            pass
        for thread in (self._worker, self._reader):
            if thread is not threading.current_thread():
                thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local browser GUI for CollaborationClient"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Local HTTP port (default 8000)"
    )
    parser.add_argument(
        "--server-host", default="127.0.0.1", help="TLS/UDP remote server host"
    )
    parser.add_argument("--tcp-port", type=int, default=9000)
    parser.add_argument(
        "--trust", type=Path, default=None, help="Trusted TLS server certificate"
    )
    args = parser.parse_args()
    bridge = LocalGUIBridge(
        port=args.port,
        server_host=args.server_host,
        tcp_port=args.tcp_port,
        trusted_cert=args.trust,
    )
    print(f"[GUI] http://127.0.0.1:{bridge.port}/", flush=True)
    print(
        f"[GUI] Remote TLS {args.server_host}:{args.tcp_port}; UDP negotiated via bootstrap",
        flush=True,
    )
    try:
        bridge.serve_forever()
    except KeyboardInterrupt:
        bridge.close()


if __name__ == "__main__":
    main()
