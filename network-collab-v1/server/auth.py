import hashlib
import hmac
import json
import getpass

from pathlib import Path


USERS_FILE = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "users.json"
)


def verify_password(username, password):
    """Fail closed on missing/corrupt local accounts; never log passwords."""
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    # Account file is local server configuration, never sent to the client.
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False
    if not isinstance(users, dict):
        return False

    user_data = users.get(username)

    if not isinstance(user_data, dict):
        return False

    # Bước 3: Lấy salt, hash và iterations
    try:
        salt = bytes.fromhex(user_data["salt"])
        stored_hash = bytes.fromhex(user_data["hash"])
        iterations = user_data["iterations"]

        if type(iterations) is not int or iterations <= 0:
            return False

        # Bước 4: Tính lại hash từ mật khẩu được nhập
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )

    except (KeyError, ValueError, TypeError):
        return False

    # Bước 5: So sánh hai hash
    return hmac.compare_digest(new_hash, stored_hash)


def main():

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    if verify_password(username, password):
        print("Đăng nhập thành công!")
    else:
        print("Sai username hoặc password!")


if __name__ == "__main__":
    main()