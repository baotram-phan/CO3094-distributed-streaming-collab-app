"""10/20 active-client integration scalability regressions using real TLS + UDP."""
import unittest

from tests.load_20_clients import run_scalability_scenario


class TestScalability10To20Clients(unittest.TestCase):
    def test_10_clients_online_and_chat(self):
        result = run_scalability_scenario(10)
        self.assertEqual(result.successful_logins, 10)
        self.assertEqual(result.simultaneous_online, 10)
        self.assertEqual(result.direct_messages_delivered, 10)
        self.assertEqual(result.broadcast_messages_delivered, 10)

    def test_20_clients_chat_and_heartbeat_after_11_seconds(self):
        result = run_scalability_scenario(20, idle_seconds=11.5)
        self.assertEqual(result.successful_logins, 20)
        self.assertEqual(result.simultaneous_online, 20)
        self.assertEqual(result.direct_messages_delivered, 20)
        self.assertEqual(result.broadcast_messages_delivered, 20)
        self.assertEqual(result.heartbeat_clients_alive, 20)
        self.assertEqual(result.post_idle_chat_delivered, 1)


if __name__ == "__main__":
    unittest.main()
