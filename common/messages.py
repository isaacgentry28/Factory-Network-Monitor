import json

NUMBER = (int, float)


def decode_json(data):
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"not valid JSON: {e}")
    if not isinstance(msg, dict):
        raise ValueError("JSON is not an object")
    return msg


def require_fields(msg, fields):
    for field, allowed in fields.items():
        if field not in msg:
            raise ValueError(f"missing field '{field}'")
        if isinstance(msg[field], bool) or not isinstance(msg[field], allowed):
            raise ValueError(f"field '{field}' has the wrong type")
        

def encode_line(msg):
    return (json.dumps(msg) + "\n").encode("utf-8")

