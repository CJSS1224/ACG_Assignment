import json
from enum import Enum

class MessageType(str, Enum):
    REGISTER = "REGISTER"
    MESSAGE = "MESSAGE"
    RETRIEVE = "RETRIEVE"

def serialize(msg_type: MessageType, body: dict) -> bytes:
    return json.dumps({"type": msg_type.value, "body": body}).encode("utf-8")

def deserialize(raw: bytes) -> dict:
    return json.loads(raw.decode("utf-8"))
