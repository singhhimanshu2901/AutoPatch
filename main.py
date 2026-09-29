#!/usr/bin/env python3
"""
main.py
=======
AutoPatch AI: Autonomous 100% Free Security Agent Orchestrator.
Scans repos with Semgrep OSS -> Synthesizes patches with Gemini API ->
Verifies in Docker Sandbox -> Human-in-the-Loop review -> Submits GitHub PRs.

Usage:
  python main.py --repo octocat/Hello-World
  python main.py --local-dir ./my-project --dry-run
"""

import argparse
import os
import sys
import time
from typing import List, Optional

# Load .env file automatically
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.prompt import Confirm, Prompt
from rich.theme import Theme

# Import local modules
from scanner import SemgrepScanner, VulnerabilityFinding
from agent_patcher import GeminiSecurityPatcher, PatchResult
from sandbox import DockerSandbox, TestExecutionResult
from git_automation import GitHubAutomator, PullRequestDetails


custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green",
    "primary": "bold blue",
})
console = Console(theme=custom_theme)


def print_banner() -> None:
    """Displays terminal header."""
    banner_text = (
        "[bold cyan]AutoPatch AI[/bold cyan] [dim]| Autonomous Security Remediation Agent[/dim]\n"
        "[dim]100% Free Stack: Semgrep OSS + Google Gemini Flash + Local Docker + PyGithub[/dim]"
    )
    console.print(Panel(banner_text, border_style="cyan", padding=(1, 2)))


def run_preflight_checks(check_github: bool = True) -> bool:
    """Verifies all external dependencies and credentials before starting."""
    console.print("\n[bold]Checking System Prerequisites...[/bold]")
    all_ok = True

    # 1. Gemini API Key
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key and not gemini_key.startswith("your_"):
        console.print("  [success]✔[/success] Google Gemini API Key configured.")
    else:
        console.print("  [danger]✘[/danger] GEMINI_API_KEY is missing in environment or .env")
        console.print("    [dim]-> Get your free key at: https://aistudio.google.com/app/apikey[/dim]")
        all_ok = False

    # 2. GitHub Token
    if check_github:
        gh_token = os.getenv("GITHUB_TOKEN")
        if gh_token and not gh_token.startswith("ghp_your"):
            console.print("  [success]✔[/success] GitHub Personal Access Token configured.")
        else:
            console.print("  [danger]✘[/danger] GITHUB_TOKEN is missing in environment or .env")
            console.print("    [dim]-> Generate token at: https://github.com/settings/tokens (scope: repo or public_repo)[/dim]")
            all_ok = False

    # 3. Docker Daemon
    try:
        sandbox = DockerSandbox()
        console.print("  [success]✔[/success] Docker daemon is running and responsive.")
    except Exception as e:
        console.print(f"  [danger]✘[/danger] Docker daemon unavailable: {str(e).splitlines()[0]}")
        console.print("    [dim]-> Start Docker Desktop or run: sudo systemctl start docker[/dim]")
        all_ok = False

    # 4. Semgrep OSS CLI
    try:
        scanner = SemgrepScanner()
        console.print("  [success]✔[/success] Semgrep OSS CLI is available.")
    except Exception as e:
        console.print(f"  [danger]✘[/danger] Semgrep OSS CLI not found: {str(e).splitlines()[0]}")
        console.print("    [dim]-> Install via: pip install semgrep or brew install semgrep[/dim]")
        all_ok = False

    console.print()
    return all_ok


def display_findings_table(findings: List[VulnerabilityFinding]) -> None:
    """Renders scan findings in a clear terminal table."""
    table = Table(title="[bold red]Security Vulnerabilities Detected[/bold red]", show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Rule ID", style="cyan")
    table.add_column("Location", style="yellow")
    table.add_column("CWE", style="dim")
    table.add_column("Risk Description")

    for idx, f in enumerate(findings, 1):
        sev_color = "red" if f.severity == "ERROR" else "yellow" if f.severity == "WARNING" else "blue"
        cwe_str = ", ".join(f.cwe[:2]) if f.cwe else "N/A"
        table.add_row(
            str(idx),
            f"[{sev_color}]{f.severity}[/{sev_color}]",
            f.check_id.split(".")[-1],
            f"{f.file_path}:{f.start_line}",
            cwe_str,
            f.message[:70] + ("..." if len(f.message) > 70 else ""),
        )

    console.print(table)


def human_review_gate(diff_str: str, file_path: str, explanation: str) -> str:
    """
    Mandatory Human-in-the-Loop review gate before pushing any code or opening a PR.
    Returns: 'approve', 'reject', or 'skip'
    """
    console.print("\n" + "=" * 70)
    console.print(Panel(
        f"[bold yellow]HUMAN-IN-THE-LOOP SAFETY REVIEW GATE[/bold yellow]\n"
        f"File: [bold]{file_path}[/bold]\n"
        f"Remediation Strategy: {explanation}",
        border_style="yellow"
    ))

    console.print("[bold cyan]Synthesized Patch Diff Preview:[/bold cyan]")
    syntax_diff = Syntax(diff_str, "diff", theme="monokai", line_numbers=True)
    console.print(syntax_diff)
    console.print("=" * 70)

    choice = Prompt.ask(
        "\n[bold green][?][/bold green] What would you like to do?",
        choices=["approve", "reject", "skip", "quit"],
        default="approve"
    )
    return choice


def run_pipeline(
    repo_name: Optional[str] = None,
    local_dir: Optional[str] = None,
    test_cmd: str = "pytest -v",
    rules_config: str = "p/security-audit",
    dry_run: bool = False,
    auto_approve: bool = False,
) -> None:
    """Executes the full remediation pipeline end-to-end."""
    print_banner()

    # Pre-flight check
    is_remote = bool(repo_name) and not dry_run
    if not run_preflight_checks(check_github=is_remote):
        console.print("[bold red]Pre-flight checks failed. Please fix the items above and re-run.[/bold red]")
        sys.exit(1)

    # Initialize components
    automator = GitHubAutomator() if repo_name else None
    scanner = SemgrepScanner(config=rules_config)
    patcher = GeminiSecurityPatcher()
    sandbox = DockerSandbox()

    # 1. Prepare codebase
    target_workspace = ""
    git_repo = None
    is_fork = False

    if repo_name:
        console.print(f"[bold primary][1/5] Setting up repository: {repo_name}[/bold primary]")
        target_workspace, git_repo, is_fork = automator.prepare_repository(repo_name)
    elif local_dir:
        target_workspace = os.path.abspath(local_dir)
        console.print(f"[bold primary][1/5] Using local directory: {target_workspace}[/bold primary]")
    else:
        console.print("[danger]Please specify either --repo <owner/repo> or --local-dir <path>[/danger]")
        sys.exit(1)

    # 2. Run Semgrep Scan
    console.print(f"\n[bold primary][2/5] Running Semgrep OSS scan (ruleset: {rules_config})...[/bold primary]")
    scan_report = scanner.scan(target_workspace)

    if scan_report.total_findings == 0:
        console.print("[success]✔ Clean scan! Zero vulnerabilities found. Repository is secure.[/success]")
        return

    display_findings_table(scan_report.findings)

    # 3. Process Findings
    console.print(f"\n[bold primary][3/5] Processing {scan_report.total_findings} security finding(s)...[/bold primary]")

    for idx, finding in enumerate(scan_report.findings, 1):
        console.print(f"\n[bold magenta]━━━━━━━━ Finding {idx}/{scan_report.total_findings}: {finding.check_id} ━━━━━━━━[/bold magenta]")
        console.print(f"Location: [yellow]{finding.file_path}:{finding.start_line}[/yellow]")
        console.print(f"Risk: {finding.message}")

        if not finding.file_content:
            console.print("[warning]File content could not be read. Skipping...[/warning]")
            continue

        # Synthesize Patch with Gemini
        with console.status(f"[bold cyan]Gemini 2.5 Flash is synthesizing surgical fix for {finding.file_path}..."):
            patch_result = patcher.generate_patch(
                file_path=finding.file_path,
                file_content=finding.file_content,
                rule_id=finding.check_id,
                message=finding.message,
                vulnerable_code=finding.vulnerable_code,
                start_line=finding.start_line,
                end_line=finding.end_line,
                cwe=finding.cwe,
            )

        if not patch_result.success:
            console.print(f"[danger]✘ Patch synthesis failed: {patch_result.error_message}[/danger]")
            continue

        console.print("[success]✔ Deterministic patch generated and syntax validated.[/success]")

        # 4. Verify in Docker Sandbox
        console.print(f"\n[bold primary][4/5] Executing test suite in ephemeral Docker sandbox ({test_cmd})...[/bold primary]")
        
        # Write patch to a temporary copy for sandbox test
        with console.status("[bold cyan]Spinning up network-isolated container & executing tests..."):
            # Apply patch to local workspace temporarily to test
            target_file_full = os.path.join(target_workspace, finding.file_path)
            orig_backup = finding.file_content
            with open(target_file_full, "w", encoding="utf-8") as f:
                f.write(patch_result.patched_code)

            test_res = sandbox.run_tests(
                repo_dir=target_workspace,
                test_command=test_cmd,
            )

            # Revert local file until human approves
            with open(target_file_full, "w", encoding="utf-8") as f:
                f.write(orig_backup)

        if not test_res.passed:
            console.print(f"[danger]✘ Sandbox tests failed (Exit Code {test_res.exit_code}):[/danger]")
            if test_res.stdout:
                console.print(test_res.stdout[:500])
            if test_res.stderr:
                console.print(test_res.stderr[:500])
            console.print("[warning]Skipping this patch to protect repository stability.[/warning]")
            continue

        console.print(f"[success]✔ Sandbox tests passed in {test_res.duration_seconds:.2f}s! Zero regressions detected.[/success]")

        # 5. Human-in-the-Loop Review Gate
        if not auto_approve:
            decision = human_review_gate(
                diff_str=patch_result.unified_diff,
                file_path=finding.file_path,
                explanation=patch_result.explanation,
            )
            if decision == "quit":
                console.print("[yellow]Exiting pipeline on user request.[/yellow]")
                break
            elif decision in ("reject", "skip"):
                console.print(f"[yellow]Patch skipped for {finding.file_path}.[/yellow]")
                continue
        else:
            console.print("[dim]Auto-approve enabled: skipping interactive prompt.[/dim]")

        # 6. Git Branch, Commit, Push, and PR
        if dry_run or not git_repo or not automator:
            console.print("\n[bold yellow][DRY-RUN][/bold yellow] Patch approved! Skipping remote push and PR creation.")
            # Apply patch locally if user wants to keep it
            keep_local = Confirm.ask("Would you like to keep this patch applied to your local workspace?", default=True)
            if keep_local:
                with open(target_file_full, "w", encoding="utf-8") as f:
                    f.write(patch_result.patched_code)
                console.print(f"[success]✔ Saved patch to {finding.file_path}[/success]")
            continue

        console.print("\n[bold primary][5/5] Creating branch, pushing to fork, and opening PR...[/bold primary]")
        branch_name = automator.apply_patch_and_create_branch(
            repo=git_repo,
            file_rel_path=finding.file_path,
            patched_content=patch_result.patched_code,
            rule_id=finding.check_id,
            commit_message=patch_result.commit_message,
        )

        automator.push_branch(git_repo, branch_name)

        pr_info = automator.create_pull_request(
            upstream_repo_name=repo_name,
            branch_name=branch_name,
            rule_id=finding.check_id,
            file_path=finding.file_path,
            explanation=patch_result.explanation,
            cwe_mitigation=patch_result.cwe_mitigation,
            unified_diff=patch_result.unified_diff,
            test_output=test_res.stdout,
            is_fork=is_fork,
        )

        console.print(Panel(
            f"[bold green]✔ PULL REQUEST CREATED SUCCESSFULLY![/bold green]\n\n"
            f"[bold]PR URL:[/bold] [link={pr_info.pr_url}]{pr_info.pr_url}[/link]\n"
            f"[bold]PR Number:[/bold] #{pr_info.pr_number}\n"
            f"[bold]Branch:[/bold] {pr_info.branch_name}\n"
            f"[bold]Target Repo:[/bold] {pr_info.upstream_repo}",
            border_style="green",
            padding=(1, 2)
        ))

    console.print("\n[bold green]Pipeline finished successfully![/bold green]")


def main() -> None:
    """CLI Argument parser entrypoint."""
    parser = argparse.ArgumentParser(
        description="AutoPatch AI: Autonomous 100% Free Security Patching Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repo",
        type=str,
        help="Target GitHub repository in 'owner/repo' format (e.g., pallets/flask)",
    )
    group.add_argument(
        "--local-dir",
        type=str,
        help="Path to a local repository or folder to scan and remediate",
    )

    parser.add_argument(
        "--test-cmd",
        type=str,
        default=os.getenv("DEFAULT_TEST_COMMAND", "pytest -v"),
        help="Test command to execute inside Docker sandbox (default: 'pytest -v')",
    )
    parser.add_argument(
        "--rules",
        type=str,
        default="p/security-audit",
        help="Semgrep rule preset or config path (default: 'p/security-audit')",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run scan, Gemini patcher, and Docker tests, but do NOT push to GitHub or create PRs",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Bypass interactive terminal confirmation gate (NOT recommended for production)",
    )

    args = parser.parse_args()

    run_pipeline(
        repo_name=args.repo,
        local_dir=args.local_dir,
        test_cmd=args.test_cmd,
        rules_config=args.rules,
        dry_run=args.dry_run,
        auto_approve=args.auto_approve,
    )


if __name__ == "__main__":
    main()
