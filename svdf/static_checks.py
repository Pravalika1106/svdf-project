# Module 1: Static Analysis Engine
# This module scans C code for vulnerable patterns using regex.
# Version: 1.1
import re
from pathlib import Path

DEFAULT_RULES = [
    {"id":"S001","pattern": r"\bstrcpy\s*\(", "message":"Use of strcpy() without bounds check", "severity":"HIGH", "fix":"Use strncpy() or bounds check"},
    {"id":"S002","pattern": r"\bgets\s*\(", "message":"Use of gets() which is unsafe", "severity":"HIGH", "fix":"Use fgets()"},
    {"id":"S003","pattern": r"\bsprintf\s*\(", "message":"Use of sprintf() without bounds check", "severity":"MEDIUM", "fix":"Use snprintf()"},

    {"id":"S004","pattern": r"\"([A-Za-z0-9_@!$%^&*()-]{8,})\"", 
        "message":"Possible hard-coded credential found", 
        "severity":"HIGH",
        "fix":"Store secrets in environment variables instead of source code."},

    {"id":"S005","pattern": r"\bsystem\s*\(", 
        "message":"Use of system() can lead to command injection", 
        "severity":"HIGH", 
        "fix":"Avoid system(); use execve() safely with proper validation"},

    {"id":"S009","pattern": r"\bstrcat\s*\(", 
        "message":"Use of strcat() without bounds check", 
        "severity":"HIGH",
        "fix":"Use strncat() with proper bounds checking"}
]


def run_static_checks(target_dir, rules=None):
    rules = rules or DEFAULT_RULES
    findings = []
    for p in Path(target_dir).rglob("*.c"):
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        for r in rules:
            for m in re.finditer(r["pattern"], text, flags=re.IGNORECASE):
                start = m.start()
                line_no = text.count("\n", 0, start) + 1
                snippet = lines[line_no-1].strip() if 0 <= line_no-1 < len(lines) else ""
                findings.append({
                    "id": r["id"],
                    "file": str(p),
                    "line": line_no,
                    "message": r["message"],
                    "severity": r["severity"],
                    "snippet": snippet,
                    "suggested_fix": r["fix"]
                })
    return findings
