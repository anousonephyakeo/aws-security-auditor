"""Reporter — formats findings into terminal output, JSON, and Markdown."""
import json
from typing import List, Dict
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "OK": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[96m",  # cyan
    "OK":       "\033[92m",  # green
    "RESET":    "\033[0m",
}


class Reporter:
    def __init__(self, findings: List[Dict]):
        self.findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "OK"), 99))

    def _color(self, severity: str) -> str:
        return SEVERITY_COLORS.get(severity, "") + severity + SEVERITY_COLORS["RESET"]

    def print_terminal(self):
        """Print color-coded findings to the terminal."""
        print(f"\n{'='*60}")
        print(f"  AWS Security Auditor — SW1ZX")
        print(f"  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"{'='*60}\n")
        if not self.findings:
            print("  ✅  No findings — environment looks clean!")
            return
        counts = {}
        for f in self.findings:
            sev = f.get("severity", "OK")
            counts[sev] = counts.get(sev, 0) + 1
            color = SEVERITY_COLORS.get(sev, "")
            reset = SEVERITY_COLORS["RESET"]
            print(f"  [{color}{sev:<8}{reset}] {f['check']:<30} | {f['resource']}")
            print(f"           → {f['message']}\n")
        print(f"{'='*60}")
        print("  Summary:", "  ".join(f"{k}: {v}" for k, v in counts.items()))
        print(f"{'='*60}\n")

    def to_json(self, path: str = None) -> str:
        data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total": len(self.findings),
            "findings": self.findings,
        }
        output = json.dumps(data, indent=2, default=str)
        if path:
            with open(path, "w") as f:
                f.write(output)
        return output

    def to_markdown(self, path: str = None) -> str:
        lines = [
            "# AWS Security Audit Report",
            f"*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*\n",
            f"**Total findings: {len(self.findings)}**\n",
            "| Severity | Check | Resource | Message |",
            "|----------|-------|----------|---------|",
        ]
        for f in self.findings:
            lines.append(f"| {f.get('severity','?')} | `{f.get('check','?')}` | `{f.get('resource','?')}` | {f.get('message','?')} |")
        output = "\n".join(lines)
        if path:
            with open(path, "w") as f:
                f.write(output)
        return output
