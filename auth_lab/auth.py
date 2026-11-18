"""Synthetic demo identity; never use this signing key outside localhost."""
import time

import jwt
from fastapi import HTTPException

DEMO_KEY = "synthetic-local-demo-signing-key-0123456789"
USERS = {"alice": (1, "alice-demo"), "bob": (2, "bob-demo")}
SERVICE_KEY = "synthetic-orders-service-token"


def login(username: str, password: str) -> str:
    record = USERS.get(username)
    if record is None or password != record[1]:
        raise HTTPException(401, "Invalid credentials")
    return jwt.encode({"sub": str(record[0]), "exp": int(time.time()) + 600,
                       "iss": "local-demo", "aud": "orders-gateway"},
                      DEMO_KEY, algorithm="HS256")


def user_id(authorization: str | None) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    try:
        payload = jwt.decode(authorization[7:], DEMO_KEY, algorithms=["HS256"],
                             issuer="local-demo", audience="orders-gateway",
                             options={"require": ["sub", "exp", "iss", "aud"]})
        subject = payload["sub"]
        if subject not in {"1", "2"}:
            raise ValueError("Unknown subject")
        return int(subject)
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(401, "Invalid token") from None
