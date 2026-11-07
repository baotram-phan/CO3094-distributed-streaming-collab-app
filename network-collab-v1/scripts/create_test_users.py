import hashlib
import secrets
import json
from pathlib import Path

USERS_FILE = Path(__file__).resolve().parent.parent / "config" / "users.json"

ITERATIONS = 200_000


def hash_password(password):
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS
    )

    return {
        "salt": salt.hex(),
        "hash": password_hash.hex(),
        "iterations": ITERATIONS
    }


def main():
    users = {
        "an": "an123456",
        "binh": "binh123456",
        "chi": "chi123456"
    }

    result = {}

    for username, password in users.items():
        result[username] = hash_password(password)

    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print("Đường dẫn file:", USERS_FILE.resolve())
    print("Dữ liệu đã ghi:", result)
    print("Created test users successfully!")


if __name__ == "__main__":
    main()