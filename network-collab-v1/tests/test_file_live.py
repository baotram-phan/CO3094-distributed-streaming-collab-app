import hashlib
from pathlib import Path
from tests import test_a_b_live_network as live


import unittest


class LiveFileTest(unittest.TestCase):
    setUp = live.RealTlsUdpTwoClientTests.setUp
    tearDown = live.RealTlsUdpTwoClientTests.tearDown
    _new_client = live.RealTlsUdpTwoClientTests._new_client

    def test_real_file(self):
        an, binh = self._new_client(), self._new_client()
        self.assertTrue(an.authenticate("an", "an123456"))
        self.assertTrue(binh.authenticate("binh", "binh123456"))
        source = Path(self.tmp.name) / "source.bin"
        target = source.with_name("received.bin")
        source.write_bytes(bytes(range(256)) * 40)
        an.offer_file("binh", source)
        offer = live._until(binh, "FILE_OFFER")
        binh.accept_file(offer["body"]["transfer_id"], target)
        for peer in (an, binh):
            self.assertEqual(
                live._until(peer, "FILE_RESULT")["body"]["status"], "COMPLETED"
            )
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertEqual(
            hashlib.sha256(target.read_bytes()).hexdigest(), offer["body"]["sha256"]
        )

    def test_large_file_chat_then_second_file(self):
        an, binh = self._new_client(), self._new_client()
        self.assertTrue(an.authenticate("an", "an123456"))
        self.assertTrue(binh.authenticate("binh", "binh123456"))
        for i, size in enumerate((2 * 1024 * 1024 + 37, 65537)):
            source = Path(self.tmp.name) / f"source{i}.bin"
            target = source.with_name(f"received{i}.bin")
            source.write_bytes((bytes(range(256)) * (size // 256 + 1))[:size])
            an.offer_file("binh", source)
            offer = live._until(binh, "FILE_OFFER")
            binh.accept_file(offer["body"]["transfer_id"], target)
            if i == 0:
                live._until(binh, "FILE_PROGRESS", timeout=30)
                an.send_direct("binh", "chat during upload")
                chat = live._until(binh, "CHAT_EVENT", timeout=30)
                self.assertEqual(chat["body"]["text"], "chat during upload")
                self.assertFalse(target.exists())
            for peer in (an, binh):
                self.assertEqual(
                    live._until(peer, "FILE_RESULT", timeout=100)["body"]["status"],
                    "COMPLETED",
                )
            self.assertEqual(target.read_bytes(), source.read_bytes())
