import hashlib
import unittest

from common.streams import StreamSendState, StreamReceiveState


class TestM6(unittest.TestCase):
    def setUp(self):
        self.file = bytes(range(256)) * 12 + b"end"  # 3075 bytes
        self.sender = StreamSendState(2)
        self.receiver = StreamReceiveState(2)

        # File stream starts with zero credit; grant permission before sending.
        self.sender.queue(self.file, fin=True)
        self.assertIsNone(self.sender.next_frame())
        self.sender.update_credit(len(self.file))
        self.receiver.grant_credit(len(self.file))

        self.frames = []
        while (frame := self.sender.next_frame()) is not None:
            self.frames.append(frame)

    def receive(self, frames):
        result = bytearray()
        for frame in frames:
            delivery = self.receiver.receive(frame.offset, frame.data, frame.fin)
            if delivery is not None:
                result.extend(delivery.data)
        return bytes(result)

    def check_file(self, received):
        self.assertTrue(self.receiver.finished)
        self.assertEqual(len(received), len(self.file))
        self.assertEqual(
            hashlib.sha256(received).digest(), hashlib.sha256(self.file).digest()
        )

    def test_01_chia_va_ghep_file(self):
        print("\n[TC6.1] An gui file cho Binh (3075 bytes)", flush=True)
        print("  DATA chunks:", [(f.offset, len(f.data)) for f in self.frames], flush=True)
        self.assertEqual([len(f.data) for f in self.frames], [1024, 1024, 1024, 3])
        self.assertTrue(self.frames[-1].fin)
        received = self.receive(self.frames)
        self.check_file(received)
        print("  Binh ghep du file, SHA-256 khop => PASS", flush=True)

    def test_02_nhan_sai_thu_tu(self):
        print("\n[TC6.2] Binh nhan A -> C -> B -> D", flush=True)
        a, b, c, d = self.frames
        first = self.receiver.receive(a.offset, a.data, a.fin)
        self.assertIsNotNone(first)
        self.assertIsNone(self.receiver.receive(c.offset, c.data, c.fin))
        print("  C den truoc B: luu dem, chua giao C", flush=True)
        middle = self.receiver.receive(b.offset, b.data, b.fin)
        self.assertIsNotNone(middle)
        last = self.receiver.receive(d.offset, d.data, d.fin)
        self.assertIsNotNone(last)
        received = first.data + middle.data + last.data
        self.check_file(received)
        print("  B den sau: ghep B+C dung vi tri, SHA-256 khop => PASS", flush=True)

    def test_03_nhan_trung(self):
        print("\n[TC6.3] Binh nhan A hai lan", flush=True)
        a = self.frames[0]
        first = self.receiver.receive(a.offset, a.data, a.fin)
        self.assertIsNotNone(first)
        self.assertIsNone(self.receiver.receive(a.offset, a.data, a.fin))
        received = first.data + self.receive(self.frames[1:])
        self.check_file(received)
        print("  Khong ghep trung A, SHA-256 khop => PASS", flush=True)


if __name__ == "__main__":
    unittest.main()
