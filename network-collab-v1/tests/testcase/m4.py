import unittest

from tests.load_20_clients import run_scalability_scenario


class TestScalability10To20Clients(unittest.TestCase):
    def test_10_clients_online_and_chat(self):
        """TC4.1: 10 ONLINE, direct/broadcast fanout, concurrent disconnect cleanup."""
        result = run_scalability_scenario(10)
        self.assertEqual(result.successful_logins, 10)
        self.assertEqual(result.simultaneous_online, 10)
        self.assertEqual(result.direct_messages_delivered, 10)
        self.assertEqual(result.broadcast_messages_delivered, 10)
        self.assertEqual(result.broadcast_deliveries_received, 100)
        self.assertEqual(result.unique_conn_ids, 10)
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.disconnected_clients, 5)
        self.assertEqual(result.remaining_online_after_disconnect, 5)
        self.assertEqual(result.offline_notifications_received, 5)
        self.assertEqual(result.post_disconnect_chat_delivered, 1)

    def test_20_clients_chat_and_heartbeat_after_11_seconds(self):
        """TC4.2: 20 ONLINE, 11.5s idle with heartbeat, chat and disconnect cleanup."""
        result = run_scalability_scenario(20, idle_seconds=11.5)
        self.assertEqual(result.successful_logins, 20)
        self.assertEqual(result.simultaneous_online, 20)
        self.assertEqual(result.direct_messages_delivered, 20)
        self.assertEqual(result.broadcast_messages_delivered, 20)
        self.assertEqual(result.broadcast_deliveries_received, 400)
        self.assertEqual(result.heartbeat_clients_alive, 20)
        self.assertEqual(result.post_idle_chat_delivered, 1)
        self.assertEqual(result.unique_conn_ids, 20)
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.disconnected_clients, 10)
        self.assertEqual(result.remaining_online_after_disconnect, 10)
        self.assertEqual(result.offline_notifications_received, 10)
        self.assertEqual(result.post_disconnect_chat_delivered, 1)


if __name__ == "__main__":
    unittest.main()
