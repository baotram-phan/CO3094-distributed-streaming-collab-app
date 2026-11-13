"""A-side terminal client: actual TLS bootstrap and reliable UDP AUTH/chat."""
from __future__ import annotations

import argparse
import getpass
from pathlib import Path
import queue
import threading

from client.core.session import CollaborationClient


def _show(event: dict) -> None:
    kind = event.get("type")
    body = event.get("body", {})
    if kind == "CHAT_EVENT":
        print(f"\n[{body.get('scope')}] {body.get('from')}: {body.get('text')}", flush=True)
    elif kind == "CHAT_ACCEPTED":
        print(f"\n[SERVER] CHAT_ACCEPTED {body.get('server_msg_id')}", flush=True)
    elif kind == "PRESENCE":
        print(f"\n[PRESENCE] {body.get('username')}: {body.get('status')}", flush=True)
    elif kind == "USER_LIST":
        print(f"\n[ONLINE] {', '.join(body.get('users', []))}", flush=True)
    elif kind in ("AUTH_OK", "AUTH_FAIL", "ERROR"):
        print(f"\n[{kind}] {body}", flush=True)
    else:
        print(f"\n[{kind}] {body}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="TLS + reliable UDP AUTH/CHAT CLI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=9000)
    ap.add_argument("--trust", type=Path, default=None)
    ap.add_argument("--user", required=True)
    args = ap.parse_args()
    password = getpass.getpass(f"Password for {args.user}: ")
    with CollaborationClient(host=args.host, tcp_port=args.tcp_port,
                             trusted_cert=args.trust) as client:
        print(f"[CONNECTED] TLS + REGISTER conn_id={client.conn_id:016x}")
        if not client.authenticate(args.user, password, timeout_s=8):
            print("[AUTH_FAIL] Sai tài khoản hoặc mật khẩu")
            return
        print("[AUTH_OK] /to <user> <message> | /all <message> | /quit")
        exit_event = threading.Event()

        def show_events():
            while not exit_event.is_set():
                try:
                    _show(client.receive_event(timeout_s=0.2))
                except queue.Empty:
                    if client.failure is not None:
                        print(f"[TRANSPORT ERROR] {client.failure}")
                        return

        listener = threading.Thread(target=show_events, daemon=True)
        listener.start()
        try:
            while not exit_event.is_set():
                line = input("chat> ").strip()
                if line == "/quit":
                    break
                if line.startswith("/to "):
                    parts = line.split(" ", 2)
                    if len(parts) != 3 or not parts[2]:
                        print("Cách dùng: /to <username> <message>")
                        continue
                    client.send_direct(parts[1], parts[2])
                elif line.startswith("/all "):
                    client.send_broadcast(line[5:])
                else:
                    print("Lệnh: /to <user> <message> | /all <message> | /quit")
                if client.failure is not None:
                    raise RuntimeError("UDP connection failed") from client.failure
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            exit_event.set()
            listener.join(timeout=1)


if __name__ == "__main__":
    main()
