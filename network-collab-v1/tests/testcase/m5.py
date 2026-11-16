import unittest

from server.router import ChatRouter, ChatRoutingError
from server.sessions import SessionRegistry


class TestM5(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(password_verifier=lambda u, p: True)
        self.ids = {}

        for port, name in enumerate(('an', 'binh', 'chi'), start=59001):
            session = self.registry.create_bootstrap(
                tcp_ip='127.0.0.1',
                c2s_key=b'A' * 32,
                s2c_key=b'B' * 32,
            )
            cid = session.conn_id
            self.registry.bind_udp_verified(cid, ('127.0.0.1', port))
            self.registry.authenticate_after_verified_udp(cid, name, 'test')
            self.ids[name] = cid

        self.router = ChatRouter(self.registry)

    def test_direct(self):
        print("\n[TC5.1] An gui cho Binh: 'Hello'", flush=True)
        plan = self.router.prepare(
            self.ids['an'], 'CHAT_DIRECT', {'to': 'binh', 'text': 'Hello'}
        )
        self.assertEqual(plan.sender, 'an')
        self.assertEqual(plan.recipients, ((self.ids['binh'], 'binh'),))
        print(" Server dinh tuyen: chi Binh", flush=True)

    def test_broadcast(self):
        print("\n[TC5.2] An gui nhom: 'Hello everyone'", flush=True)
        plan = self.router.prepare(
            self.ids['an'], 'CHAT_BROADCAST', {'text': 'Hello everyone'}
        )
        expected = {(cid, name) for name, cid in self.ids.items()}
        self.assertEqual(set(plan.recipients), expected)
        print(" Server dinh tuyen: tat ca", flush=True)

    def test_offline(self):
        self.registry.close(self.ids['chi'], reason='logout')
        print("\n[TC5.4] Chi offline. An gui cho Chi 'Hello'. Binh gui cho Chi 'Hello'", flush=True)
        with self.assertRaises(ChatRoutingError) as err:
            self.router.prepare(
                self.ids['an'], 'CHAT_DIRECT', {'to': 'chi', 'text': 'Hello'}
            )
            self.router.prepare(
                self.ids['binh'], 'CHAT_DIRECT', {'to': 'chi', 'text': 'Hello'}
            )
        self.assertEqual(err.exception.code, 'USER_OFFLINE')
        print("Server tu choi: USER_OFFLINE", flush=True)


if __name__ == '__main__':
    unittest.main()
