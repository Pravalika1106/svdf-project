import click
import os
from .static_checks import run_static_checks
from .sanitizer_runner import compile_with_sanitizers, run_binary
from .fuzzer import run_mutation_fuzz
from .utils import write_json, ensure_dir, timestamp
import pathlib

REPORTS_DIR = "reports"
REPRO_DIR = "reproducers"

@click.group()
def cli():
    """svdf - Security Vulnerability Detection Framework (CLI)"""
    pass

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--out", default="reports/report.json", help="Path for JSON report")
@click.option("--fuzz/--no-fuzz", default=True, help="Run mutational fuzzer (simple)")
@click.option("--iterations", default=200, help="Fuzzer iterations")
def scan(target, out, fuzz, iterations):
    """
    Scan TARGET directory (source files) and produce report JSON.
    """
    ensure_dir(REPRO_DIR)
    ensure_dir(REPORTS_DIR)

    report = {
        "generated_at": timestamp(),
        "target": str(target),
        "static_findings": [],
        "sanitizer": {},
        "fuzzer_crashes": []
    }

    click.echo("[*] Running static checks...")
    static_findings = run_static_checks(target)
    report["static_findings"] = static_findings
    click.echo(f"  -> static findings: {len(static_findings)}")

    # try to compile each .c file and run sanitizer
    for cfile in pathlib.Path(target).rglob("*.c"):
        click.echo(f"[*] Attempting to compile {cfile} with sanitizers...")
        rc, out_compile, err_compile, binpath = compile_with_sanitizers(str(cfile))
        report["sanitizer"].setdefault(str(cfile), {})
        report["sanitizer"][str(cfile)]["compile_returncode"] = rc
        report["sanitizer"][str(cfile)]["compile_stdout"] = out_compile
        report["sanitizer"][str(cfile)]["compile_stderr"] = err_compile
        if rc == 0:
            click.echo(f"[*] Running binary {binpath} with no input (simple run)...")
            rc2, o2, e2 = run_binary(binpath, input_data=None)
            report["sanitizer"][str(cfile)]["run_returncode"] = rc2
            report["sanitizer"][str(cfile)]["run_stdout"] = o2
            report["sanitizer"][str(cfile)]["run_stderr"] = e2

            if fuzz:
                click.echo("[*] Running simple mutational fuzzer...")
                # create a small seeds list (if sample input exists)
                seeds = []
                # look for files in sample folder of same name .in
                sample_in = cfile.with_suffix(".in")
                if sample_in.exists():
                    seeds.append(str(sample_in))
                # fallback seed
                if not seeds:
                    # write a default seed
                    default_seed = os.path.join(REPRO_DIR, "seed.bin")
                    open(default_seed,"wb").write(b"AAAA")
                    seeds = [default_seed]
                crashes = run_mutation_fuzz(binpath, seeds, iterations=iterations)
                report["fuzzer_crashes"].extend(crashes)
                click.echo(f"  -> crashes found: {len(crashes)}")
        else:
            click.echo(f"  ! compile failed for {cfile}, see report")

    write_json(out, report)
    click.echo(f"[+] Report written to {out}")
    click.echo("[+] Done.")

if __name__ == "__main__":
    cli()
