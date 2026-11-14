"""File relay control and binary forwarding on dynamically allocated streams.

Each peer participates in at most one active transfer. The receiver confirms
application blocks and verifies SHA-256 before the server reports completion.
"""

import re
import secrets
import threading

from common.constants import MAX_FILE_SIZE


class FileRelay:
    def __init__(self, registry, transport):
        self.registry = registry
        self.transport = transport
        self.lock = threading.RLock()
        self.active = {}
        self.next_stream = 2

    def control(self, conn, message):
        """Validate a control request and return response intents for stream 0."""
        body, kind, req = message["body"], message["type"], message["id"]

        def error(code):
            return [(conn, "ERROR", {"code": code, "message": kind}, req)]

        with self.lock:
            if kind == "FILE_OFFER":
                name, size, digest = (
                    body.get(k) for k in ("filename", "size", "sha256")
                )
                if (
                    not isinstance(name, str)
                    or not 1 <= len(name) <= 255
                    or type(size) is not int
                    or not 0 < size <= MAX_FILE_SIZE
                    or not isinstance(digest, str)
                    or not re.fullmatch("[0-9a-f]{64}", digest)
                    or not isinstance(body.get("to"), str)
                ):
                    return error("BAD_FRAME")
                peer = self.registry.find_online(body["to"])
                if peer is None or peer.conn_id == conn:
                    return error("USER_OFFLINE")
                dest = peer.conn_id
                if any(c in self.active for c in (conn, dest)):
                    return error("TRANSFER_BUSY")
                tid = secrets.token_hex(16)
                meta = dict(transfer_id=tid, filename=name, size=size, sha256=digest)
                t = dict(src=conn, dst=dest, meta=meta, stage="offer", offset=0)
                # Both peers point to the same transfer, preventing overlaps.
                self.active[conn] = self.active[dest] = t
                return [
                    (conn, "FILE_OFFER_ACK", {"transfer_id": tid}, req),
                    (
                        dest,
                        "FILE_OFFER",
                        {**meta, "from": self.registry.get(conn).username},
                        None,
                    ),
                ]
            t = self.active.get(conn)
            if not t or body.get("transfer_id") != t["meta"]["transfer_id"]:
                return error("TRANSFER_NOT_FOUND")
            src, dst, meta = t["src"], t["dst"], t["meta"]
            if kind == "FILE_ACCEPT" and conn == dst and t["stage"] == "offer":
                # A fresh stream prevents offsets from an older file being reused.
                t["stream"] = self.next_stream
                self.next_stream += 1
                for c in (src, dst):
                    self.transport.open_file_stream(c, t["stream"])
                t["stage"] = "start"
                return [
                    (
                        c,
                        "FILE_START",
                        {**meta, "role": role, "stream_id": t["stream"]},
                        None,
                    )
                    for c, role in ((dst, "receiver"), (src, "sender"))
                ]
            if kind == "FILE_READY" and conn == src and t["stage"] == "start":
                self.transport.allow_file_input(src, t["stream"])
                t["stage"] = "data"
                return []
            # Receiver-confirmed bytes release the next application block.
            if kind == "FILE_CONTINUE" and conn == dst and t["stage"] == "data":
                offset = body.get("offset")
                if type(offset) is not int or offset != t["offset"]:
                    return error("BAD_FRAME")
                return [
                    (
                        src,
                        kind,
                        {"transfer_id": meta["transfer_id"], "offset": offset},
                        None,
                    )
                ]
            if kind == "FILE_REJECT" and conn == dst and t["stage"] == "offer":
                status = "REJECTED"
            elif kind == "FILE_DONE" and conn == dst and t["stage"] == "fin":
                status = "COMPLETED" if body.get("sha256_ok") is True else "FAILED"
            else:
                return error("BAD_FRAME")
            if "stream" in t:
                for c in (src, dst):
                    self.transport.close_file_stream(c, t["stream"])
            del self.active[src], self.active[dst]
            return [
                (
                    c,
                    "FILE_RESULT",
                    {"transfer_id": meta["transfer_id"], "status": status},
                    None,
                )
                for c in (src, dst)
            ]

    def relay(self, conn, stream, offset, data, fin):
        """Forward contiguous sender bytes; FIN must match the declared size."""
        with self.lock:
            t = self.active.get(conn)
            if (
                not t
                or t["src"] != conn
                or t["stage"] != "data"
                or stream != t["stream"]
            ):
                return False
            end = offset + len(data)
            if (
                offset != t["offset"]
                or end > t["meta"]["size"]
                or (fin and end != t["meta"]["size"])
            ):
                return False
            self.transport.queue_reliable_bytes(t["dst"], stream, data, fin=fin)
            t["offset"] = end
            if fin:
                t["stage"] = "fin"
            return True

    def closed(self, conn):
        """Release both peer entries and report failure to the remaining peer."""
        with self.lock:
            t = self.active.pop(conn, None)
            if t:
                other = t["dst"] if conn == t["src"] else t["src"]
                self.active.pop(other, None)
                if "stream" in t:
                    self.transport.close_file_stream(other, t["stream"])
                return other, {
                    "transfer_id": t["meta"]["transfer_id"],
                    "status": "FAILED",
                    "reason": "PEER_DISCONNECTED",
                }
