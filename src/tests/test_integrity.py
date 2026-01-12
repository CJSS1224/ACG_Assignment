from src.crypto.integrity import hash_message

def test_hash_message():
    h = hash_message(b"abc")
    assert isinstance(h, bytes)
    assert len(h) == 32
