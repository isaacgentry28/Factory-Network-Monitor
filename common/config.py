import os
from pathlib import Path

COMMON_DIR = Path(__file__).resolve().parent

def _read_env_file(path):
    values = {}
    if not path.exists():
        return values
    for line_no, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path.name} line {line_no}: expected KEY=VALUE, got {raw!r}")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values

_values = {
    **_read_env_file(COMMON_DIR / "config.env"),
    **_read_env_file(COMMON_DIR / "secrets.env"),
    **os.environ,
}

def get(key, default=None):

    value = _values.get(key, "")
    if value != "":
        return value
    if default is not None:
        return str(default)
    raise KeyError(f"setting {key} is missing or blank - add it in the common/config.env or secrets.env")

def get_int(key, default=None):
    return int(get(key, default))

def get_float(key, default=None):
    return float(get(key, default))