import json
import sys, os
# ensure project dir is in path (so `from svdf...` works when running this file directly)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from svdf.static_checks import run_static_checks
from svdf.sanitizer_runner import compile_with_sanitizers, run_binary
from svdf.fuzzer import run_mutation_fuzz
from svdf.utils import write_json, ensure_dir, timestamp
import pathlib

def main():
    target = "samples"
    out = "reports/report.json"
    iterations = 100

    ensure_dir("reports")
    ensure_dir("reproducers")

    report = {
        "generated_at": timestamp(),
        "target": target,
        "static_findings": [],
        "sanitizer": {},
        "fuzzer_crashes": []
    }

    print("[*] Running static checks...")
    static_results = run_static_checks(target)
    report["static_findings"] = static_results
    print("  -> Found", len(static_results), "issues")

    for cfile in pathlib.Path(target).rglob("*.c"):
        print("[*] Compiling:", cfile)
        rc, cout, cerr, binpath = compile_with_sanitizers(str(cfile))
        report["sanitizer"][str(cfile)] = {
            "compile_returncode": rc,
            "compile_stdout": cout,
            "compile_stderr": cerr
        }

        if rc == 0:
            print("[*] Running:", binpath)
            rc2, o2, e2 = run_binary(binpath)
            report["sanitizer"][str(cfile)]["run_returncode"] = rc2
            report["sanitizer"][str(cfile)]["run_stdout"] = o2
            report["sanitizer"][str(cfile)]["run_stderr"] = e2

            print("[*] Starting simple fuzzer...")
            # create seeds similar to CLI behavior
            seeds = []
            sample_in = pathlib.Path(cfile).with_suffix(".in")
            if sample_in.exists():
                seeds.append(str(sample_in))
            if not seeds:
                default_seed = os.path.join("reproducers", "seed.bin")
                open(default_seed,"wb").write(b"AAAA")
                seeds = [default_seed]

            crashes = run_mutation_fuzz(binpath, seeds, iterations)
            report["fuzzer_crashes"].extend(crashes)
            print("  -> Crashes found:", len(crashes))
        else:
            print("[!] compile failed for", cfile)

    write_json(out, report)
    print("[+] Report saved to", out)

if __name__ == "__main__":
    main()
