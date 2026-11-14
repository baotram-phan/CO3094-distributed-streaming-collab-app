import unittest

from server.auth import verify_password


class TestAuthentication(unittest.TestCase):

    def test_correct_password(self):
        result = verify_password("an", "an123456")
        self.assertTrue(result)

    def test_wrong_password(self):
        result = verify_password("an", "wrongpassword")
        self.assertFalse(result)

    def test_unknown_username(self):
        result = verify_password("nam", "nam123456")
        self.assertFalse(result)

    def test_another_correct_user(self):
        result = verify_password("binh", "binh123456")
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
