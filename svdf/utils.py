import json
import os
import time
from pathlib import Path

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def write_json(path, data):
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_json(path):
    with open(path) as f:
        return json.load(f)

def timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
