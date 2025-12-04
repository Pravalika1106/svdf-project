import subprocess
import shlex
import os
from pathlib import Path
from .utils import ensure_dir, timestamp

BUILD_DIR = ".svdf_build"

def compile_with_sanitizers(source_path, out_name="target_bin"):
    ensure_dir(BUILD_DIR)
    out_path = os.path.join(BUILD_DIR, out_name)
    cmd = f"gcc -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 {shlex.quote(source_path)} -o {shlex.quote(out_path)}"
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, proc.stdout, proc.stderr, out_path

def run_binary(binary_path, input_data=None, timeout=5):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
    # If input_data is bytes we pass bytes and capture bytes, then decode for the report.
    try:
        if isinstance(input_data, (bytes, bytearray)):
            proc = subprocess.run([binary_path], input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
            out = proc.stdout.decode(errors="ignore") if isinstance(proc.stdout, (bytes, bytearray)) else str(proc.stdout)
            err = proc.stderr.decode(errors="ignore") if isinstance(proc.stderr, (bytes, bytearray)) else str(proc.stderr)
            return proc.returncode, out, err
        else:
            proc = subprocess.run([binary_path], input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, env=env)
            return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -1, "", "BINARY_NOT_FOUND"
