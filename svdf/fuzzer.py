import random
import time
from pathlib import Path
import subprocess
import os
from .utils import ensure_dir

REPRO_DIR = "reproducers"

def mutate(data: bytes) -> bytes:
    if not data:
        data = b"AAAA"
    b = bytearray(data)
    n = max(1, len(b)//10)
    for _ in range(n):
        idx = random.randrange(0, len(b))
        b[idx] = random.randrange(1, 255)
    # sometimes insert random bytes
    if random.random() < 0.2:
        b += bytes([random.randrange(0,255) for _ in range(random.randrange(1,8))])
    return bytes(b)

def run_mutation_fuzz(binary_path, seeds, iterations=200, timeout=3):
    ensure_dir(REPRO_DIR)
    crashes = []
    # Build corpus: if seeds is empty, use default corpus
    corpus = []
    for s in seeds:
        try:
            corpus.append(open(s,"rb").read())
        except Exception:
            continue
    if not corpus:
        corpus = [b"AAAA"]  # fallback seed

    for it in range(iterations):
        seed = random.choice(corpus)
        input_data = mutate(seed)
        try:
            proc = subprocess.run([binary_path], input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            rc = proc.returncode
            out = proc.stdout.decode(errors="ignore") if isinstance(proc.stdout, (bytes, bytearray)) else str(proc.stdout)
            err = proc.stderr.decode(errors="ignore") if isinstance(proc.stderr, (bytes, bytearray)) else str(proc.stderr)
        except subprocess.TimeoutExpired:
            rc = -1
            out = ""
            err = "TIMEOUT"
        except FileNotFoundError:
            rc = -1
            out = ""
            err = "BINARY_NOT_FOUND"

        # detect crash-ish
        if rc != 0 or ("error" in err.lower()) or ("segmentation" in err.lower()) or ("asan" in err.lower()):
            # save repro
            t = int(time.time()*1000)
            fname = f"{REPRO_DIR}/crash_{t}.bin"
            with open(fname,"wb") as f:
                f.write(input_data)
            logname = f"{REPRO_DIR}/crash_{t}.log"
            with open(logname,"w", encoding="utf-8") as f:
                f.write(f"rc: {rc}\nstdout:\n{out}\nstderr:\n{err}\n")
            crashes.append({"input":fname, "log":logname, "rc":rc})
            # add to corpus to further mutate
            corpus.append(input_data)
    return crashes
