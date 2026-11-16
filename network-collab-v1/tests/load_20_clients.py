"""Real-socket 10/20-client scalability scenario (not a simulated registry fixture).

All test users/certificates are created in a temporary directory. This test
performs real TLS HELLO, UDP REGISTER, reliable AUTH and CHAT. It measures
successful application deliveries and connection stability rather than claiming
throughput from mocked callbacks or browser tab counts.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import hashlib
import json
from pathlib import Path
import queue
import secrets
import tempfile
import threading
import time
from unittest.mock import patch

from client.core.session import CollaborationClient
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionState


CLIENT_PASSWORD = "benchmark-only-password"  # Only written as PBKDF2 hashes.


def _percentile_ms(samples_s: list[float], fraction: float) -> float:
    ordered = sorted(samples_s)
    if not ordered:
        return 0.0
    # nearest-rank with a 1-based rank, then convert to 0-based index
    from math import ceil
    index = min(len(ordered) - 1, max(0, ceil(len(ordered) * fraction) - 1))
    return round(ordered[index] * 1000, 2)


@dataclass
class ScalabilityResult:
    clients: int
    concurrent_login_workers: int
    successful_logins: int
    simultaneous_online: int
    unique_conn_ids: int
    direct_messages_delivered: int
    broadcast_messages_delivered: int
    heartbeat_clients_alive: int | None
    post_idle_chat_delivered: int
    login_total_seconds: float
    login_p50_ms: float
    login_p95_ms: float
    direct_p95_ms: float
    broadcast_fanout_seconds: float
    idle_seconds: float
    errors: int = 0
    disconnected_clients: int = 0
    remaining_online_after_disconnect: int = 0
    offline_notifications_received: int = 0
    post_disconnect_chat_delivered: int = 0
    broadcast_deliveries_received: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _next_message(client: CollaborationClient, predicate, *, deadline: float):
    """Drain pre-existing presence/control events until a target CHAT_EVENT arrives."""
    encountered = []
    while time.monotonic() < deadline:
        if client.failure:
            raise AssertionError(f"client UDP worker failed: {type(client.failure).__name__}")
        try:
            event = client.receive_event(timeout_s=max(0.001, min(0.2, deadline - time.monotonic())))
        except queue.Empty:
            continue
        if predicate(event):
            return event
        if len(encountered) < 12:
            encountered.append(event.get("type", "?"))
    raise AssertionError(f"CHAT_EVENT timeout for conn_id={client.conn_id:016x}; first ignored events={encountered}")


def run_scalability_scenario(
    number_of_clients: int,
    *,
    login_workers: int | None = None,
    idle_seconds: float = 0.0,
) -> ScalabilityResult:
    """Exercise N ONLINE clients, chat/heartbeat, then disconnect half concurrently.

    Raises AssertionError/other exceptions on failure, never silently retries
    application messages. This test intentionally uses default 10-second idle
    timeout to verify that B5.2 PING/PONG is working when idle_seconds >= 11.
    """
    if number_of_clients not in (10, 20):
        raise ValueError("Benchmark supports exactly 10 or 20 clients")
    if idle_seconds < 0:
        raise ValueError("idle_seconds must be nonnegative")
    workers = min(number_of_clients, 8) if login_workers is None else login_workers
    if not (1 <= workers <= number_of_clients):
        raise ValueError("login_workers must be within 1..clients")

    with tempfile.TemporaryDirectory(prefix="co3094_scalability_") as directory:
        root = Path(directory)
        cert, key = generate_certificate(root / "cert")
        accounts = {}
        usernames = [f"load{i:02d}" for i in range(number_of_clients)]
        for name in usernames:
            salt = secrets.token_bytes(16)
            accounts[name] = {
                "salt": salt.hex(),
                "hash": hashlib.pbkdf2_hmac(
                    "sha256", CLIENT_PASSWORD.encode("utf-8"), salt, 200_000
                ).hex(),
                "iterations": 200_000,
            }
        users_file = root / "accounts.json"
        users_file.write_text(json.dumps(accounts), encoding="utf-8")

        clients = [CollaborationClient(host="127.0.0.1", tcp_port=0, trusted_cert=cert)
                   for _ in usernames]
        with patch("server.auth.USERS_FILE", users_file):
            server = CollaborationServer(
                host="127.0.0.1", tcp_port=0, udp_port=0,
                cert=cert, key=key, logger=None
            )
            for client in clients:
                client.tcp_port = server.tcp_port
            server_thread = threading.Thread(
                target=server.serve_forever, daemon=True, name="load-test-server"
            )
            server_thread.start()
            try:
                def login(index: int) -> tuple[int, float]:
                    started = time.monotonic()
                    client = clients[index]
                    client.connect()
                    if not client.authenticate(usernames[index], CLIENT_PASSWORD,
                                               timeout_s=15.0):
                        raise AssertionError(f"AUTH rejected for {usernames[index]}")
                    return index, time.monotonic() - started

                login_start = time.monotonic()
                durations: list[float] = []
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(login, index)
                               for index in range(number_of_clients)]
                    for future in as_completed(futures):
                        index, elapsed = future.result(timeout=28)
                        durations.append(elapsed)
                        assert clients[index].conn_id is not None
                login_elapsed = time.monotonic() - login_start

                online = server.registry.list_online_users()
                assert set(online) == set(usernames), (
                    f"Expected {number_of_clients} ONLINE; got {len(online)}: {online}"
                )
                conn_ids = {client.conn_id for client in clients}
                assert len(conn_ids) == number_of_clients, "ConnIDs must be unique"
                assert all(
                    server.registry.get(client.conn_id).state is SessionState.ONLINE
                    for client in clients
                ), "All sessions must be ONLINE at the SAME instant"

                # Each client sends a distinct direct message to its next peer.
                direct_send_at = []
                for index, client in enumerate(clients):
                    direct_send_at.append(time.monotonic())
                    client.send_direct(usernames[(index + 1) % number_of_clients],
                                       f"ring:{index}")
                direct_latencies = []
                direct_deadline = time.monotonic() + 18.0
                for recipient_index, receiver in enumerate(clients):
                    sender_index = (recipient_index - 1) % number_of_clients
                    expected_sender = usernames[sender_index]
                    event = _next_message(
                        receiver,
                        lambda e, sn=expected_sender, si=sender_index:
                            e.get("type") == "CHAT_EVENT"
                            and e.get("body", {}).get("from") == sn
                            and e.get("body", {}).get("text") == f"ring:{si}"
                            and e.get("body", {}).get("scope") == "direct",
                        deadline=direct_deadline,
                    )
                    assert event["body"]["from"] == expected_sender
                    direct_latencies.append(time.monotonic() - direct_send_at[sender_index])

                # Each client broadcasts once; every message must reach ALL
                # clients (including its sender), for N*N received deliveries.
                fanout_start = time.monotonic()
                broadcasts = {
                    username: f"benchmark-global:{index}"
                    for index, username in enumerate(usernames)
                }
                for username, client in zip(usernames, clients):
                    client.send_broadcast(broadcasts[username])
                fanout_deadline = fanout_start + 18.0
                broadcast_deliveries = 0
                for receiver in clients:
                    pending_broadcasts = dict(broadcasts)
                    while pending_broadcasts:
                        event = _next_message(
                            receiver,
                            lambda e: e.get("type") == "CHAT_EVENT"
                                and e.get("body", {}).get("from") in pending_broadcasts
                                and e.get("body", {}).get("text")
                                    == pending_broadcasts.get(e.get("body", {}).get("from"))
                                and e.get("body", {}).get("scope") == "broadcast",
                            deadline=fanout_deadline,
                        )
                        del pending_broadcasts[event["body"]["from"]]
                        broadcast_deliveries += 1
                fanout_elapsed = time.monotonic() - fanout_start

                # Idle check includes >10s default idle timeout for 20 clients.
                if idle_seconds:
                    time.sleep(idle_seconds)
                online_after_idle = server.registry.list_online_users()
                assert set(online_after_idle) == set(usernames), (
                    "Client disconnected during heartbeat check: "
                    f"{set(usernames) - set(online_after_idle)}"
                )
                alive = 0
                for client in clients:
                    assert client.failure is None, f"Client failed: {client.failure!r}"
                    assert not client._stop.is_set(), "Client worker stopped"
                    assert server.registry.get(client.conn_id).state is SessionState.ONLINE
                    if client.udp and client.udp._last_pong_timestamp_ms is not None:
                        alive += 1
                post_idle_delivered = 0
                if idle_seconds >= 2:
                    assert alive == number_of_clients, (
                        f"Only {alive}/{number_of_clients} clients received a PONG"
                    )
                    clients[0].send_direct(usernames[1], "post-idle-check")
                    _next_message(
                        clients[1],
                        lambda e: e.get("type") == "CHAT_EVENT"
                            and e.get("body", {}).get("from") == usernames[0]
                            and e.get("body", {}).get("text") == "post-idle-check",
                        deadline=time.monotonic() + 8.0,
                    )
                    post_idle_delivered = 1

                # Stop half the actual clients together. No server-side close,
                # fake clock or longer idle timeout: cleanup must happen naturally.
                drop_count = number_of_clients // 2
                dropped = clients[:drop_count]
                survivors = clients[drop_count:]
                drop_barrier = threading.Barrier(drop_count)

                def disconnect(client: CollaborationClient) -> None:
                    drop_barrier.wait(timeout=5.0)
                    client.close()

                with ThreadPoolExecutor(max_workers=drop_count) as pool:
                    futures = [pool.submit(disconnect, client) for client in dropped]
                    for future in futures:
                        future.result(timeout=8.0)

                pending_offline = set(usernames[:drop_count])
                offline_deadline = time.monotonic() + server.registry.idle_timeout_s + 8.0
                while pending_offline:
                    event = _next_message(
                        survivors[-1],
                        lambda e: e.get("type") == "PRESENCE"
                            and e.get("body", {}).get("status") == "offline"
                            and e.get("body", {}).get("username") in pending_offline,
                        deadline=offline_deadline,
                    )
                    pending_offline.remove(event["body"]["username"])

                remaining_online = server.registry.list_online_users()
                assert set(remaining_online) == set(usernames[drop_count:]), (
                    f"Wrong ONLINE users after disconnect: {remaining_online}"
                )
                assert server.udp_service.connection_ids() == {
                    client.conn_id for client in survivors
                }, "Transport state must contain only surviving clients"
                for client in dropped:
                    assert server.registry.get(client.conn_id) is None
                    assert server.udp_service.get_reliable_receiver(client.conn_id) is None
                for client in survivors:
                    assert client.failure is None, f"Survivor failed: {client.failure!r}"
                    assert not client._stop.is_set(), "Surviving client stopped"

                survivors[0].send_direct(usernames[-1], "after-concurrent-disconnect")
                _next_message(
                    survivors[-1],
                    lambda e: e.get("type") == "CHAT_EVENT"
                        and e.get("body", {}).get("from") == usernames[drop_count]
                        and e.get("body", {}).get("text") == "after-concurrent-disconnect"
                        and e.get("body", {}).get("scope") == "direct",
                    deadline=time.monotonic() + 8.0,
                )

                result = ScalabilityResult(
                    clients=number_of_clients,
                    concurrent_login_workers=workers,
                    successful_logins=len(durations),
                    simultaneous_online=len(online),
                    unique_conn_ids=len(conn_ids),
                    direct_messages_delivered=len(direct_latencies),
                    broadcast_messages_delivered=number_of_clients,
                    heartbeat_clients_alive=alive if idle_seconds >= 2 else None,
                    post_idle_chat_delivered=post_idle_delivered,
                    login_total_seconds=round(login_elapsed, 3),
                    login_p50_ms=_percentile_ms(durations, 0.50),
                    login_p95_ms=_percentile_ms(durations, 0.95),
                    direct_p95_ms=_percentile_ms(direct_latencies, 0.95),
                    broadcast_fanout_seconds=round(fanout_elapsed, 3),
                    idle_seconds=idle_seconds,
                    disconnected_clients=drop_count,
                    remaining_online_after_disconnect=len(remaining_online),
                    offline_notifications_received=drop_count,
                    post_disconnect_chat_delivered=1,
                    broadcast_deliveries_received=broadcast_deliveries,
                )
                print("[SCALABILITY] " + json.dumps(result.to_dict(), sort_keys=True),
                      flush=True)
                return result
            finally:
                for client in clients:
                    client.close()
                server.stop()
                server_thread.join(timeout=3.0)
