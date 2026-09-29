"""
scanner.py
==========
Runs local Semgrep OSS static analysis on a target repository and parses
findings into typed, normalized vulnerability reports.

100% Free Stack: Uses Semgrep OSS CLI with community rulesets (no cloud account required).
"""

import json
import os
import shutil
import subprocess
import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    """Normalized representation of a static analysis vulnerability."""
    check_id: str = Field(description="Unique identifier of the rule (e.g., bandit/semgrep ID)")
    file_path: str = Field(description="Relative path to the vulnerable file")
    start_line: int = Field(description="1-based starting line of the vulnerable code")
    end_line: int = Field(description="1-based ending line of the vulnerable code")
    message: str = Field(description="Detailed explanation of the security risk")
    severity: str = Field(default="WARNING", description="Severity level: ERROR, WARNING, or INFO")
    cwe: List[str] = Field(default_factory=list, description="Common Weakness Enumeration identifiers")
    owasp: List[str] = Field(default_factory=list, description="OWASP category mappings")
    vulnerable_code: str = Field(default="", description="Code snippet directly flagged by the scanner")
    file_content: Optional[str] = Field(default=None, description="Full file content for patch generation context")


class ScanReport(BaseModel):
    """Aggregated scan findings for a repository."""
    target_path: str
    total_findings: int
    findings: List[VulnerabilityFinding]
    scan_time_seconds: float
    raw_errors: List[str] = Field(default_factory=list)


class SemgrepScanner:
    """
    Executes local Semgrep OSS scans without telemetry or paid cloud dependencies.
    """

    def __init__(self, config: str = "p/security-audit", timeout: int = 120):
        """
        :param config: Semgrep rule pack (e.g., 'p/security-audit', 'p/owasp-top-ten', 'p/python', 'auto')
        :param timeout: Maximum seconds before terminating the scan process
        """
        self.config = config
        self.timeout = timeout
        self._verify_installation()

    def _verify_installation(self) -> None:
        """Verifies that Semgrep CLI is installed and accessible in the system PATH."""
        if not shutil.which("semgrep"):
            # Check if installed via python module
            try:
                subprocess.run(
                    ["python", "-m", "semgrep", "--version"],
                    capture_output=True,
                    check=True,
                )
                self._executable = ["python", "-m", "semgrep"]
            except Exception:
                raise EnvironmentError(
                    "Semgrep OSS CLI is not installed or not in PATH.\n"
                    "Install it for free via:\n"
                    "  pip install semgrep\n"
                    "  or (macOS): brew install semgrep"
                )
        else:
            self._executable = ["semgrep"]

    def scan(
        self,
        target_dir: str,
        custom_rules: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
    ) -> ScanReport:
        """
        Runs Semgrep on target_dir, returning parsed and typed VulnerabilityFindings.

        :param target_dir: Absolute or relative path to the cloned repository
        :param custom_rules: Override the default rule configuration
        :param severity_filter: List of severities to include (e.g., ['ERROR', 'WARNING'])
        :param exclude_dirs: Directories to ignore during scanning
        """
        target_dir = os.path.abspath(target_dir)
        if not os.path.exists(target_dir):
            raise FileNotFoundError(f"Target directory does not exist: {target_dir}")

        rules_arg = custom_rules or self.config
        exclude_list = exclude_dirs or [
            "tests",
            "test",
            "venv",
            ".venv",
            "node_modules",
            ".git",
            "dist",
            "build",
        ]

        cmd = [
            *self._executable,
            "scan",
            "--config",
            rules_arg,
            "--json",
            "--quiet",
            "--disable-version-check",
            "--no-git-ignore",  # Ensure all source files in checkout are scanned
        ]

        for exc in exclude_list:
            cmd.extend(["--exclude", exc])

        cmd.append(target_dir)

        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,  # Semgrep exits with 1 if findings are found
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Semgrep scan exceeded {self.timeout}s timeout on {target_dir}")
        except Exception as e:
            raise RuntimeError(f"Failed to execute Semgrep: {str(e)}")

        duration = time.time() - start_time
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Parse JSON output
        findings: List[VulnerabilityFinding] = []
        raw_errors: List[str] = []

        if not stdout:
            if stderr:
                raw_errors.append(stderr)
            return ScanReport(
                target_path=target_dir,
                total_findings=0,
                findings=[],
                scan_time_seconds=duration,
                raw_errors=raw_errors,
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            raw_errors.append(f"Invalid JSON returned by Semgrep: {stdout[:500]}")
            return ScanReport(
                target_path=target_dir,
                total_findings=0,
                findings=[],
                scan_time_seconds=duration,
                raw_errors=raw_errors,
            )

        # Collect raw errors or warnings from semgrep report
        for err in data.get("errors", []):
            raw_errors.append(f"[{err.get('level', 'ERROR')}] {err.get('message', '')}")

        # Normalize results
        results = data.get("results", [])
        for item in results:
            check_id = item.get("check_id", "unknown-rule")
            extra = item.get("extra", {})
            raw_severity = extra.get("severity", "WARNING").upper()

            if severity_filter and raw_severity not in [s.upper() for s in severity_filter]:
                continue

            metadata = extra.get("metadata", {})
            cwe_entries = metadata.get("cwe", [])
            if isinstance(cwe_entries, str):
                cwe_entries = [cwe_entries]
            owasp_entries = metadata.get("owasp", [])
            if isinstance(owasp_entries, str):
                owasp_entries = [owasp_entries]

            rel_file_path = os.path.relpath(item.get("path", ""), target_dir)
            abs_file_path = os.path.join(target_dir, rel_file_path)

            full_content: Optional[str] = None
            if os.path.exists(abs_file_path) and os.path.isfile(abs_file_path):
                try:
                    with open(abs_file_path, "r", encoding="utf-8", errors="replace") as f:
                        full_content = f.read()
                except Exception:
                    full_content = None

            snippet = extra.get("lines", "")
            start = item.get("start", {}).get("line", 1)
            end = item.get("end", {}).get("line", start)

            findings.append(
                VulnerabilityFinding(
                    check_id=check_id,
                    file_path=rel_file_path,
                    start_line=start,
                    end_line=end,
                    message=extra.get("message", "Security vulnerability detected by Semgrep OSS"),
                    severity=raw_severity,
                    cwe=cwe_entries,
                    owasp=owasp_entries,
                    vulnerable_code=snippet,
                    file_content=full_content,
                )
            )

        # Sort findings by severity (ERROR first, then WARNING, then INFO)
        severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        findings.sort(key=lambda x: severity_order.get(x.severity, 3))

        return ScanReport(
            target_path=target_dir,
            total_findings=len(findings),
            findings=findings,
            scan_time_seconds=duration,
            raw_errors=raw_errors,
        )


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Scanning {target} using Semgrep OSS (security-audit rules)...")
    scanner = SemgrepScanner(config="p/security-audit")
    report = scanner.scan(target)
    print(f"[+] Scan completed in {report.scan_time_seconds:.2f}s. Found {report.total_findings} issues.")
    for idx, f in enumerate(report.findings, 1):
        print(f"  {idx}. [{f.severity}] {f.check_id} at {f.file_path}:{f.start_line}")
        print(f"     Message: {f.message}")
