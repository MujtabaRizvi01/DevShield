import json

def validate_json(json_string: str):
    try:
        json.loads(json_string)
        return True
    except json.JSONDecodeError:
        return False
