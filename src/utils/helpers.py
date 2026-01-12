import time
import base64
import json
from typing import Any

def timestamp_now() -> float:
    return time.time()

def bytes_to_base64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def base64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def format_message(username: str, payload: Any) -> str:
    return json.dumps({"user": username, "payload": payload})
