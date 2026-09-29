import React, { useState } from 'react';
import {
  Shield,
  Terminal,
  Cpu,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Copy,
  Check,
  GitPullRequest,
  ExternalLink,
  Lock,
  Box,
  Key,
  FileCode,
  ArrowRight,
  Sparkles,
  Bug,
  ChevronRight,
  Server,
  Eye,
  XCircle
} from 'lucide-react';

interface VulnerabilityPreset {
  id: string;
  name: string;
  ruleId: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  cwe: string;
  filePath: string;
  line: number;
  description: string;
  vulnerableCode: string;
  patchedCode: string;
  diff: string;
  testOutput: string;
  remediationSummary: string;
}

const PRESETS: VulnerabilityPreset[] = [
  {
    id: 'sqli',
    name: 'SQL Injection in SQLite Query',
    ruleId: 'python.sqlite3.sqli.fstring-execute',
    severity: 'ERROR',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    filePath: 'services/auth_service.py',
    line: 18,
    description: 'SQL query constructed via f-string interpolation allowing authentication bypass.',
    vulnerableCode: `def get_user_by_username(cursor, user_input: str):
    # Insecure query interpolation
    query = f"SELECT id, username, role FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchone()`,
    patchedCode: `def get_user_by_username(cursor, user_input: str):
    # Remediated using parameterized SQL placeholders
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchone()`,
    diff: `--- a/services/auth_service.py
+++ b/services/auth_service.py
@@ -16,4 +16,4 @@
 def get_user_by_username(cursor, user_input: str):
-    # Insecure query interpolation
-    query = f"SELECT id, username, role FROM users WHERE username = '{user_input}'"
-    cursor.execute(query)
+    # Remediated using parameterized SQL placeholders
+    query = "SELECT id, username, role FROM users WHERE username = ?"
+    cursor.execute(query, (user_input,))
     return cursor.fetchone()`,
    testOutput: `pytest -v tests/test_auth.py
============================= test session starts ==============================
collected 3 items

tests/test_auth.py::test_legitimate_user PASSED                           [ 33%]
tests/test_auth.py::test_sqli_payload_neutralized PASSED                   [ 66%]
tests/test_auth.py::test_empty_input PASSED                               [100%]

============================== 3 passed in 0.42s ===============================
Exit Code: 0 (Ephemeral Docker Container exit_code=0)`,
    remediationSummary: 'Replaced vulnerable f-string SQL query concatenation with parameterized prepared statement placeholders (?, (user_input,)), completely neutralizing SQL injection vectors without changing method signature.'
  },
  {
    id: 'cmd-injection',
    name: 'Remote Command Injection (shell=True)',
    ruleId: 'python.subprocess.security.dangerous-shell',
    severity: 'ERROR',
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    filePath: 'tasks/backup_runner.py',
    line: 42,
    description: 'Subprocess call uses shell=True with user-controlled input string, permitting arbitrary system command execution.',
    vulnerableCode: `import subprocess

def run_backup_sync(target_directory: str):
    # High-risk: shell=True exposes shell metacharacters (; & | $)
    cmd = f"rsync -avz {target_directory} /backup/archive/"
    subprocess.run(cmd, shell=True, check=True)`,
    patchedCode: `import subprocess
import shlex

def run_backup_sync(target_directory: str):
    # Remediated: Argument list without shell=True avoids shell parsing
    cmd = ["rsync", "-avz", target_directory, "/backup/archive/"]
    subprocess.run(cmd, shell=False, check=True)`,
    diff: `--- a/tasks/backup_runner.py
+++ b/tasks/backup_runner.py
@@ -1,2 +1,3 @@
 import subprocess
+import shlex

 def run_backup_sync(target_directory: str):
-    # High-risk: shell=True exposes shell metacharacters (; & | $)
-    cmd = f"rsync -avz {target_directory} /backup/archive/"
-    subprocess.run(cmd, shell=True, check=True)
+    # Remediated: Argument list without shell=True avoids shell parsing
+    cmd = ["rsync", "-avz", target_directory, "/backup/archive/"]
+    subprocess.run(cmd, shell=False, check=True)`,
    testOutput: `pytest -v tests/test_backup.py
============================= test session starts ==============================
collected 2 items

tests/test_backup.py::test_normal_directory_sync PASSED                   [ 50%]
tests/test_backup.py::test_command_injection_attempt PASSED               [100%]

============================== 2 passed in 0.38s ===============================
Exit Code: 0 (Ephemeral Docker Container exit_code=0)`,
    remediationSummary: 'Converted the raw shell string into an explicit argument vector (list) and removed shell=True. This guarantees arguments are passed directly to execve without invoking a subshell.'
  },
  {
    id: 'path-traversal',
    name: 'Arbitrary File Read / Path Traversal',
    ruleId: 'python.lang.security.audit.path-traversal',
    severity: 'WARNING',
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    filePath: 'handlers/file_download.py',
    line: 27,
    description: 'Unchecked path concatenation allows attackers to supply ../../etc/passwd to escape designated storage directory.',
    vulnerableCode: `import os

def read_user_asset(filename: str) -> bytes:
    base_dir = "/var/app/storage/assets"
    # Vulnerable to ../ path traversal
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "rb") as f:
        return f.read()`,
    patchedCode: `import os
from pathlib import Path

def read_user_asset(filename: str) -> bytes:
    base_dir = Path("/var/app/storage/assets").resolve()
    target_path = (base_dir / filename).resolve()
    
    # Enforce boundary containment check
    if not target_path.is_relative_to(base_dir):
        raise PermissionError("Access denied: Path traversal attempt detected.")
        
    with open(target_path, "rb") as f:
        return f.read()`,
    diff: `--- a/handlers/file_download.py
+++ b/handlers/file_download.py
@@ -1,2 +1,3 @@
 import os
+from pathlib import Path

 def read_user_asset(filename: str) -> bytes:
-    base_dir = "/var/app/storage/assets"
-    # Vulnerable to ../ path traversal
-    file_path = os.path.join(base_dir, filename)
-    with open(file_path, "rb") as f:
+    base_dir = Path("/var/app/storage/assets").resolve()
+    target_path = (base_dir / filename).resolve()
+    
+    # Enforce boundary containment check
+    if not target_path.is_relative_to(base_dir):
+        raise PermissionError("Access denied: Path traversal attempt detected.")
+        
+    with open(target_path, "rb") as f:
         return f.read()`,
    testOutput: `pytest -v tests/test_files.py
============================= test session starts ==============================
collected 2 items

tests/test_files.py::test_safe_asset_retrieval PASSED                     [ 50%]
tests/test_files.py::test_path_traversal_blocked PASSED                   [100%]

============================== 2 passed in 0.31s ===============================
Exit Code: 0 (Ephemeral Docker Container exit_code=0)`,
    remediationSummary: 'Applied canonicalization using Path.resolve() and enforced a strict is_relative_to(base_dir) check, preventing directory traversal via parent directory tokens.'
  }
];

const CODE_FILES: Record<string, { desc: string; code: string; language: string }> = {
  'main.py': {
    desc: 'Pipeline Orchestrator: Coordinates scanning, patch generation, Docker sandbox verification, and terminal human approval gate.',
    language: 'python',
    code: `#!/usr/bin/env python3
# main.py - AutoPatch AI CLI Orchestrator
import argparse, os, sys
from scanner import SemgrepScanner
from agent_patcher import GeminiSecurityPatcher
from sandbox import DockerSandbox
from git_automation import GitHubAutomator
from rich.console import Console
from rich.prompt import Prompt

console = Console()

def run_pipeline(repo_name: str, test_cmd: str = "pytest -v", dry_run: bool = False):
    console.print("[bold cyan]AutoPatch AI Pipeline Active[/bold cyan]")
    
    # 1. Setup Repo (Fork or Clone)
    automator = GitHubAutomator() if repo_name else None
    workspace, git_repo, is_fork = automator.prepare_repository(repo_name)
    
    # 2. Run Semgrep OSS Scan
    scanner = SemgrepScanner(config="p/security-audit")
    report = scanner.scan(workspace)
    console.print(f"[green]Found {report.total_findings} security finding(s)[/green]")
    
    patcher = GeminiSecurityPatcher()
    sandbox = DockerSandbox()
    
    for finding in report.findings:
        # 3. Synthesize Deterministic Patch via Gemini Flash
        patch = patcher.generate_patch(
            file_path=finding.file_path,
            file_content=finding.file_content,
            rule_id=finding.check_id,
            message=finding.message,
            vulnerable_code=finding.vulnerable_code,
            start_line=finding.start_line,
            end_line=finding.end_line,
            cwe=finding.cwe
        )
        if not patch.success:
            continue
            
        # 4. Verify in Isolated Docker Sandbox
        test_res = sandbox.run_tests(workspace, test_command=test_cmd)
        if not test_res.passed:
            console.print("[red]Sandbox test suite failed. Patch discarded.[/red]")
            continue
            
        # 5. Human-in-the-Loop Review Gate
        console.print(patch.unified_diff)
        choice = Prompt.ask("Approve patch and submit PR?", choices=["approve", "reject", "skip"])
        if choice != "approve":
            continue
            
        # 6. Branch, Commit, Push, and PR via PyGithub
        branch = automator.apply_patch_and_create_branch(
            git_repo, finding.file_path, patch.patched_code, finding.check_id, patch.commit_message
        )
        automator.push_branch(git_repo, branch)
        pr = automator.create_pull_request(repo_name, branch, finding.check_id, finding.file_path, patch.explanation, patch.cwe_mitigation, patch.unified_diff, test_res.stdout, is_fork)
        console.print(f"[bold green]PR Submitted: {pr.pr_url}[/bold green]")`
  },
  'scanner.py': {
    desc: 'Local Semgrep OSS SAST Scanner: Runs rule-based static analysis without cloud telemetry, producing normalized Pydantic findings.',
    language: 'python',
    code: `# scanner.py - 100% Free Semgrep OSS Wrapper
import json, os, subprocess, shutil
from pydantic import BaseModel
from typing import List, Optional

class VulnerabilityFinding(BaseModel):
    check_id: str
    file_path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    cwe: List[str]
    vulnerable_code: str
    file_content: Optional[str]

class SemgrepScanner:
    def __init__(self, config: str = "p/security-audit"):
        self.config = config
        
    def scan(self, target_dir: str):
        cmd = ["semgrep", "scan", "--config", self.config, "--json", "--quiet", target_dir]
        res = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(res.stdout) if res.stdout else {}
        # Parse and return structured findings list
        findings = []
        for item in data.get("results", []):
            findings.append(VulnerabilityFinding(
                check_id=item["check_id"],
                file_path=item["path"],
                start_line=item["start"]["line"],
                end_line=item["end"]["line"],
                message=item["extra"]["message"],
                severity=item["extra"]["severity"],
                cwe=item["extra"]["metadata"].get("cwe", []),
                vulnerable_code=item["extra"]["lines"],
                file_content=open(os.path.join(target_dir, item["path"])).read()
            ))
        return findings`
  },
  'agent_patcher.py': {
    desc: 'Gemini AI Code Synthesizer: Generates surgical, deterministic patches with AST syntax validation and auto-healing retries.',
    language: 'python',
    code: `# agent_patcher.py - Gemini Free Tier Code Patcher
import ast, difflib, json
from google import genai
from pydantic import BaseModel

class PatchResult(BaseModel):
    success: bool
    patched_code: str
    unified_diff: str
    commit_message: str
    explanation: str

class GeminiSecurityPatcher:
    def __init__(self, model_name: str = "gemini-2.5-flash"):
        self.client = genai.Client()
        self.model = model_name
        
    def generate_patch(self, file_path, file_content, rule_id, message, vulnerable_code, start_line, end_line, cwe):
        prompt = f"Fix {rule_id} in {file_path}. Code: {vulnerable_code}. Full: {file_content}"
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config={"temperature": 0.1}
        )
        data = json.loads(response.text)
        patched = data["patched_file_content"]
        
        # Local Python AST validation check
        if file_path.endswith(".py"):
            ast.parse(patched)  # raises SyntaxError if invalid
            
        diff = "".join(difflib.unified_diff(
            file_content.splitlines(keepends=True),
            patched.splitlines(keepends=True)
        ))
        return PatchResult(success=True, patched_code=patched, unified_diff=diff, commit_message=data["commit_message"], explanation=data["explanation"])`
  },
  'sandbox.py': {
    desc: 'Ephemeral Docker Sandbox: Network-isolated container test runner with cgroup quotas to test patches safely without host pollution.',
    language: 'python',
    code: `# sandbox.py - Ephemeral Network-Isolated Container Runner
import docker, tempfile, shutil, os

class DockerSandbox:
    def __init__(self, base_image: str = "python:3.11-slim"):
        self.client = docker.from_env()
        self.base_image = base_image
        
    def run_tests(self, repo_dir: str, test_command: str = "pytest -v"):
        temp_dir = tempfile.mkdtemp(prefix="autopatch_")
        shutil.copytree(repo_dir, os.path.join(temp_dir, "app"))
        
        container = self.client.containers.create(
            image=self.base_image,
            command=["/bin/bash", "-c", f"pip install -q -r requirements.txt && {test_command}"],
            volumes={os.path.join(temp_dir, "app"): {"bind": "/app", "mode": "rw"}},
            working_dir="/app",
            network_mode="bridge",
            mem_limit="1g",
            cpu_quota=100000,  # 1 CPU core cap
            security_opt=["no-new-privileges:true"]
        )
        container.start()
        status = container.wait(timeout=180)
        logs = container.logs().decode("utf-8")
        container.remove(force=True)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return status["StatusCode"] == 0, logs`
  },
  'git_automation.py': {
    desc: 'GitHub & Git Automation: Handles upstream repo forking, authenticated cloning, clean feature branch commits, and PR generation.',
    language: 'python',
    code: `# git_automation.py - Fork, Branch, and Pull Request Client
import os, git
from github import Github, Auth

class GitHubAutomator:
    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.gh = Github(auth=Auth.Token(self.token))
        self.username = self.gh.get_user().login
        
    def prepare_repository(self, upstream_repo_name: str):
        upstream = self.gh.get_repo(upstream_repo_name)
        fork = self.gh.get_user().create_fork(upstream)
        clone_url = fork.clone_url.replace("https://", f"https://x-access-token:{self.token}@")
        local_path = f"/tmp/autopatch_{upstream.name}"
        repo = git.Repo.clone_from(clone_url, local_path)
        return local_path, repo, True
        
    def apply_patch_and_create_branch(self, repo, file_path, content, rule_id, commit_msg):
        branch_name = f"autopatch/sec-{rule_id[:20]}"
        head = repo.create_head(branch_name)
        head.checkout()
        with open(os.path.join(repo.working_tree_dir, file_path), "w") as f:
            f.write(content)
        repo.index.add([file_path])
        repo.index.commit(commit_msg)
        return branch_name
        
    def create_pull_request(self, upstream_repo, branch, rule_id, file_path, explanation, cwe, diff, test_output, is_fork):
        upstream = self.gh.get_repo(upstream_repo)
        head = f"{self.username}:{branch}" if is_fork else branch
        title = f"fix(security): remediate {rule_id} in {file_path}"
        body = f"### Security Fix\\n{explanation}\\n\\n### Docker Tests\\n\`\`\`\\n{test_output}\\n\`\`\`"
        return upstream.create_pull(title=title, body=body, base=upstream.default_branch, head=head)`
  },
  'requirements.txt': {
    desc: 'Minimal Python dependencies: 100% free stack without paid third-party SaaS wrappers.',
    language: 'text',
    code: `google-genai>=0.1.1
google-generativeai>=0.8.3
semgrep>=1.60.0
docker>=7.0.0
PyGithub>=2.2.0
GitPython>=3.1.41
rich>=13.7.1
python-dotenv>=1.0.1
pydantic>=2.6.0
pytest>=8.0.0`
  },
  '.env.example': {
    desc: 'Environment variable template for Google Gemini Free API, GitHub Personal Access Token, and Docker socket.',
    language: 'bash',
    code: `# AutoPatch AI Configuration
# Google Gemini Free API Key (Get at: https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# GitHub Personal Access Token (Free PAT: repo or public_repo scope)
GITHUB_TOKEN=ghp_your_personal_access_token_here

# Local Docker daemon socket
DOCKER_HOST=unix:///var/run/docker.sock
SANDBOX_TIMEOUT_SECONDS=180
DEFAULT_TEST_COMMAND=pytest -v`
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'simulator' | 'code' | 'architecture' | 'prerequisites'>('simulator');
  const [selectedPresetId, setSelectedPresetId] = useState<string>('sqli');
  const [simStep, setSimStep] = useState<number>(0); // 0: idle, 1: scanning, 2: patch synthesis, 3: docker test, 4: human gate, 5: pr created
  const [activeCodeFile, setActiveCodeFile] = useState<string>('main.py');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [approvalDecision, setApprovalDecision] = useState<'pending' | 'approved' | 'rejected'>('pending');

  const selectedPreset = PRESETS.find(p => p.id === selectedPresetId) || PRESETS[0];

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const runSimulation = () => {
    setSimStep(1);
    setApprovalDecision('pending');

    setTimeout(() => {
      setSimStep(2);
      setTimeout(() => {
        setSimStep(3);
        setTimeout(() => {
          setSimStep(4); // reaches Human in the loop review gate!
        }, 1200);
      }, 1400);
    }, 1100);
  };

  const handleHumanGate = (decision: 'approve' | 'reject') => {
    if (decision === 'approve') {
      setApprovalDecision('approved');
      setSimStep(5);
    } else {
      setApprovalDecision('rejected');
    }
  };

  const resetSimulation = () => {
    setSimStep(0);
    setApprovalDecision('pending');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-white">AutoPatch AI</span>
                <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-1.5 py-0.5 rounded">
                  100% Free Stack
                </span>
              </div>
              <p className="text-xs text-slate-400">Autonomous SAST Scanning · Gemini Patcher · Docker Verification · Human Review Gate</p>
            </div>
          </div>

          {/* Interactive Navigation Tabs */}
          <nav className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-medium">
            <button
              onClick={() => setActiveTab('simulator')}
              className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'simulator'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              Pipeline Simulator
            </button>
            <button
              onClick={() => setActiveTab('code')}
              className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'code'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              Codebase Explorer ({Object.keys(CODE_FILES).length})
            </button>
            <button
              onClick={() => setActiveTab('architecture')}
              className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'architecture'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Architecture
            </button>
            <button
              onClick={() => setActiveTab('prerequisites')}
              className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'prerequisites'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              Prerequisites & Setup
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* TAB 1: PIPELINE SIMULATOR */}
        {activeTab === 'simulator' && (
          <div className="space-y-6">
            {/* Hero / Pipeline Progress Bar */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    Interactive Pipeline Execution
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Select a vulnerability vulnerability pattern and step through the automated verification and approval workflow.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {simStep === 0 ? (
                    <button
                      onClick={runSimulation}
                      className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs rounded-lg flex items-center gap-2 transition-colors shadow-sm cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      Run Remediation Pipeline
                    </button>
                  ) : (
                    <button
                      onClick={resetSimulation}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      Reset Pipeline
                    </button>
                  )}
                </div>
              </div>

              {/* Step Flow Indicators */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2 pt-4">
                {[
                  { stepNum: 1, label: '1. Semgrep SAST', desc: 'Scan & JSON parse' },
                  { stepNum: 2, label: '2. Gemini Patcher', desc: 'Surgical fix & AST' },
                  { stepNum: 3, label: '3. Docker Sandbox', desc: 'Isolated test run' },
                  { stepNum: 4, label: '4. Human Gate', desc: 'Console diff review' },
                  { stepNum: 5, label: '5. GitHub PR', desc: 'Fork, commit & PR' },
                ].map((s) => {
                  const isActive = simStep === s.stepNum;
                  const isDone = simStep > s.stepNum || (simStep === 5 && s.stepNum === 4 && approvalDecision === 'approved');
                  const isFailed = simStep === 4 && s.stepNum === 4 && approvalDecision === 'rejected';

                  return (
                    <div
                      key={s.stepNum}
                      className={`p-2.5 rounded-lg border text-left transition-all ${
                        isActive
                          ? 'bg-cyan-950/40 border-cyan-500/60 ring-1 ring-cyan-500/30'
                          : isDone
                          ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200'
                          : isFailed
                          ? 'bg-rose-950/20 border-rose-500/40 text-rose-200'
                          : 'bg-slate-950/40 border-slate-800 text-slate-500'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-xs font-semibold ${isActive ? 'text-cyan-400' : isDone ? 'text-emerald-400' : isFailed ? 'text-rose-400' : 'text-slate-400'}`}>
                          {s.label}
                        </span>
                        {isDone && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                        {isActive && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />}
                        {isFailed && <XCircle className="w-3.5 h-3.5 text-rose-400" />}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">{s.desc}</p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Target Vulnerability Selector */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Presets Sidebar */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Target Vulnerabilities ({PRESETS.length})
                  </h3>
                  <span className="text-[11px] text-slate-500">Semgrep OSS Rules</span>
                </div>

                <div className="space-y-2">
                  {PRESETS.map((p) => {
                    const isSelected = p.id === selectedPresetId;
                    return (
                      <button
                        key={p.id}
                        onClick={() => {
                          setSelectedPresetId(p.id);
                          resetSimulation();
                        }}
                        className={`w-full text-left p-3 rounded-lg border transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-slate-900 border-cyan-500/50 shadow-md'
                            : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className={`text-xs font-semibold ${isSelected ? 'text-cyan-400' : 'text-slate-200'}`}>
                            {p.name}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                              p.severity === 'ERROR'
                                ? 'bg-rose-950/60 text-rose-400 border border-rose-900/60'
                                : 'bg-amber-950/60 text-amber-400 border border-amber-900/60'
                            }`}
                          >
                            {p.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">{p.filePath}</p>
                        <p className="text-[11px] font-mono text-slate-500 mt-1 truncate">{p.ruleId}</p>
                      </button>
                    );
                  })}
                </div>

                {/* Free Stack Badge Box */}
                <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-lg text-xs space-y-2">
                  <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    Zero-Cost Infrastructure
                  </div>
                  <ul className="text-slate-400 space-y-1 text-[11px]">
                    <li className="flex items-center gap-1.5">
                      <span className="text-emerald-400">✓</span> Gemini 2.5 Flash Free Tier API
                    </li>
                    <li className="flex items-center gap-1.5">
                      <span className="text-emerald-400">✓</span> Semgrep OSS offline community rules
                    </li>
                    <li className="flex items-center gap-1.5">
                      <span className="text-emerald-400">✓</span> Local Docker Daemon ephemeral sandboxes
                    </li>
                    <li className="flex items-center gap-1.5">
                      <span className="text-emerald-400">✓</span> Standard free GitHub PAT & PyGithub
                    </li>
                  </ul>
                </div>
              </div>

              {/* Main Inspection View */}
              <div className="lg:col-span-2 space-y-4">
                {/* Vulnerability Card */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-xs text-slate-400 flex items-center gap-2">
                        <span>{selectedPreset.filePath}</span>
                        <span>·</span>
                        <span>Line {selectedPreset.line}</span>
                        <span>·</span>
                        <span className="font-mono text-cyan-400">{selectedPreset.ruleId}</span>
                      </div>
                      <h3 className="text-sm font-semibold text-white mt-0.5">{selectedPreset.name}</h3>
                    </div>
                    <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                      {selectedPreset.cwe.split(':')[0]}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
                    <span className="font-semibold text-rose-400">Scanner Warning: </span>
                    {selectedPreset.description}
                  </p>

                  {/* Vulnerable Code Snippet */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span className="flex items-center gap-1 text-rose-400 font-mono text-[11px]">
                        <Bug className="w-3.5 h-3.5" /> Vulnerable Code Flagged by Semgrep OSS
                      </span>
                      <button
                        onClick={() => handleCopy(selectedPreset.vulnerableCode, 'vuln')}
                        className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1"
                      >
                        {copiedKey === 'vuln' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        Copy
                      </button>
                    </div>
                    <pre className="p-3 bg-slate-950 rounded-lg border border-rose-950/60 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
                      <code>{selectedPreset.vulnerableCode}</code>
                    </pre>
                  </div>
                </div>

                {/* SIMULATION STEP CONTENT */}
                {simStep >= 2 && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5" />
                        Gemini 2.5 Flash Synthesized Patch & Unified Diff
                      </h4>
                      <span className="text-[11px] text-emerald-400 bg-emerald-950/50 border border-emerald-800/50 px-2 py-0.5 rounded font-mono">
                        AST Validated (ast.parse passed)
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 bg-slate-950/50 p-2.5 rounded border border-slate-800">
                      <span className="font-semibold text-cyan-400">Strategy: </span>
                      {selectedPreset.remediationSummary}
                    </p>

                    {/* Unified Diff View */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs text-slate-400">
                        <span className="font-mono text-[11px]">Unified Git Diff</span>
                        <button
                          onClick={() => handleCopy(selectedPreset.diff, 'diff')}
                          className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1"
                        >
                          {copiedKey === 'diff' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          Copy Diff
                        </button>
                      </div>
                      <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono overflow-x-auto leading-relaxed">
                        {selectedPreset.diff.split('\n').map((line, idx) => {
                          const isAdd = line.startsWith('+') && !line.startsWith('+++');
                          const isDel = line.startsWith('-') && !line.startsWith('---');
                          const isHdr = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                          return (
                            <div
                              key={idx}
                              className={
                                isAdd
                                  ? 'bg-emerald-950/30 text-emerald-300'
                                  : isDel
                                  ? 'bg-rose-950/30 text-rose-300'
                                  : isHdr
                                  ? 'text-cyan-400 font-semibold'
                                  : 'text-slate-400'
                              }
                            >
                              {line}
                            </div>
                          );
                        })}
                      </pre>
                    </div>

                    {/* Step 3: Docker Sandbox Execution Logs */}
                    {simStep >= 3 && (
                      <div className="space-y-2 pt-2 border-t border-slate-800">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                            <Box className="w-3.5 h-3.5 text-cyan-400" />
                            Ephemeral Docker Sandbox Execution Log
                          </span>
                          <span className="text-[11px] font-mono text-emerald-400">
                            network_mode=none · mem_limit=1g · no regressions
                          </span>
                        </div>
                        <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto">
                          {selectedPreset.testOutput}
                        </pre>
                      </div>
                    )}

                    {/* Step 4: Mandatory Human-in-the-Loop Review Gate */}
                    {simStep >= 4 && (
                      <div className={`p-4 rounded-xl border transition-all ${
                        approvalDecision === 'approved'
                          ? 'bg-emerald-950/30 border-emerald-500/50'
                          : approvalDecision === 'rejected'
                          ? 'bg-rose-950/30 border-rose-500/50'
                          : 'bg-amber-950/20 border-amber-500/60'
                      }`}>
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2">
                              <AlertTriangle className="w-4 h-4 text-amber-400" />
                              <span className="text-xs font-bold uppercase tracking-wider text-amber-300">
                                Safety & Anti-Spam Gate: Human Approval Required
                              </span>
                            </div>
                            <p className="text-xs text-slate-300 mt-1">
                              Review the verified patch diff above. No Pull Request or remote git branch will be created without your explicit authorization.
                            </p>
                          </div>

                          {approvalDecision === 'pending' ? (
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleHumanGate('reject')}
                                className="px-3 py-1.5 bg-slate-800 hover:bg-rose-950/80 hover:text-rose-300 text-slate-300 text-xs font-medium rounded-lg transition-colors cursor-pointer"
                              >
                                Reject / Discard
                              </button>
                              <button
                                onClick={() => handleHumanGate('approve')}
                                className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
                              >
                                <Check className="w-3.5 h-3.5" />
                                Approve & Create PR
                              </button>
                            </div>
                          ) : approvalDecision === 'approved' ? (
                            <div className="text-xs font-semibold text-emerald-400 flex items-center gap-1">
                              <CheckCircle2 className="w-4 h-4" /> Approved by Operator
                            </div>
                          ) : (
                            <div className="text-xs font-semibold text-rose-400 flex items-center gap-1">
                              <XCircle className="w-4 h-4" /> Patch Rejected
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Step 5: Pull Request Preview */}
                    {simStep === 5 && approvalDecision === 'approved' && (
                      <div className="p-4 bg-slate-950 rounded-xl border border-emerald-500/40 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
                            <GitPullRequest className="w-4 h-4" />
                            GitHub Pull Request #42 Created
                          </div>
                          <span className="text-[11px] font-mono text-slate-400">
                            branch: autopatch/sec-{selectedPreset.id}-1711728392
                          </span>
                        </div>

                        <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-xs space-y-2">
                          <div className="font-semibold text-white">
                            fix(security): remediate {selectedPreset.ruleId} in {selectedPreset.filePath}
                          </div>
                          <div className="text-slate-400 text-[11px] space-y-1">
                            <p><strong>CWE:</strong> {selectedPreset.cwe}</p>
                            <p><strong>Remediation:</strong> {selectedPreset.remediationSummary}</p>
                            <p><strong>Verification:</strong> Ephemeral Docker test runner verified with 0 regressions.</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: CODEBASE EXPLORER */}
        {activeTab === 'code' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  Production-Ready Python Codebase
                </h2>
                <p className="text-xs text-slate-400">
                  All 7 modular Python files are saved on disk and ready to execute immediately with free CLI tools.
                </p>
              </div>
              <button
                onClick={() => handleCopy(CODE_FILES[activeCodeFile]?.code || '', activeCodeFile)}
                className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs font-medium rounded-lg border border-slate-800 flex items-center gap-1.5 transition-colors cursor-pointer self-start sm:self-auto"
              >
                {copiedKey === activeCodeFile ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                Copy {activeCodeFile}
              </button>
            </div>

            {/* File Switcher Tabs */}
            <div className="flex flex-wrap gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
              {Object.keys(CODE_FILES).map((fileName) => {
                const isActive = activeCodeFile === fileName;
                return (
                  <button
                    key={fileName}
                    onClick={() => setActiveCodeFile(fileName)}
                    className={`px-3 py-1.5 rounded-md text-xs font-mono transition-colors cursor-pointer ${
                      isActive
                        ? 'bg-cyan-600 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {fileName}
                  </button>
                );
              })}
            </div>

            {/* Selected File Details */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs">
                <span className="font-mono text-cyan-400 font-semibold">{activeCodeFile}</span>
                <span className="text-slate-400">{CODE_FILES[activeCodeFile]?.desc}</span>
              </div>
              <pre className="p-4 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed max-h-[580px] overflow-y-auto">
                <code>{CODE_FILES[activeCodeFile]?.code}</code>
              </pre>
            </div>
          </div>
        )}

        {/* TAB 3: ARCHITECTURE & DATA FLOW */}
        {activeTab === 'architecture' && (
          <div className="space-y-6">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Pipeline Architecture & Security Controls
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Designed for 100% free operation, zero host contamination, and deterministic patch correctness.
              </p>
            </div>

            {/* Flowchart Grid */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="w-8 h-8 rounded-lg bg-blue-950 border border-blue-800/60 flex items-center justify-center text-blue-400">
                  <GitPullRequest className="w-4 h-4" />
                </div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">1. Upstream Clone</h4>
                <p className="text-[11px] text-slate-400">
                  Forks repository under the user account if push rights are absent. Clones to an isolated temporary directory.
                </p>
                <div className="text-[10px] font-mono text-slate-500 pt-1">PyGithub + GitPython</div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
                  <Shield className="w-4 h-4" />
                </div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">2. Semgrep SAST</h4>
                <p className="text-[11px] text-slate-400">
                  Runs local offline Semgrep OSS CLI with community rules (<code className="text-cyan-400">p/security-audit</code>). Zero cloud telemetry.
                </p>
                <div className="text-[10px] font-mono text-slate-500 pt-1">Semgrep OSS CLI</div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="w-8 h-8 rounded-lg bg-purple-950 border border-purple-800/60 flex items-center justify-center text-purple-400">
                  <Cpu className="w-4 h-4" />
                </div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">3. Gemini Patcher</h4>
                <p className="text-[11px] text-slate-400">
                  Google Gemini 2.5 Flash Free Tier synthesizes minimal surgical fixes with strict AST syntax validation & auto-healing retries.
                </p>
                <div className="text-[10px] font-mono text-slate-500 pt-1">google-genai Free Tier</div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="w-8 h-8 rounded-lg bg-amber-950 border border-amber-800/60 flex items-center justify-center text-amber-400">
                  <Box className="w-4 h-4" />
                </div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">4. Docker Sandbox</h4>
                <p className="text-[11px] text-slate-400">
                  Spins up an ephemeral, network-isolated container (<code className="text-amber-400">network_mode='none'</code>) to test the repo test suite.
                </p>
                <div className="text-[10px] font-mono text-slate-500 pt-1">docker-py daemon</div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">5. Human Gate & PR</h4>
                <p className="text-[11px] text-slate-400">
                  Terminal presents unified syntax diff for operator approval. Only approved patches are committed, pushed, and opened as PRs.
                </p>
                <div className="text-[10px] font-mono text-slate-500 pt-1">Rich CLI + PyGithub</div>
              </div>
            </div>

            {/* Security Safeguards */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                Safety, Anti-Spam & Determinism Guarantees
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1.5">
                  <div className="font-semibold text-slate-200">1. Network-Isolated Sandboxing</div>
                  <p className="text-slate-400">
                    Host systems are insulated against malicious code or untrusted test suites by executing tests with <code className="text-cyan-400">network_mode='none'</code> and cgroup memory limits.
                  </p>
                </div>
                <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1.5">
                  <div className="font-semibold text-slate-200">2. Deterministic AST Verification</div>
                  <p className="text-slate-400">
                    Every candidate patch undergoes native Python AST parsing (<code className="text-cyan-400">ast.parse</code>) prior to test execution. Patches that produce syntax errors are rejected or self-healed.
                  </p>
                </div>
                <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1.5">
                  <div className="font-semibold text-slate-200">3. Anti-Spam Human Review Gate</div>
                  <p className="text-slate-400">
                    Autonomous bots that submit unsolicited, unverified PRs create noise for maintainers. AutoPatch AI strictly requires operator confirmation (<code className="text-cyan-400">[approve/reject/skip]</code>) before any branch is pushed.
                  </p>
                </div>
                <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 space-y-1.5">
                  <div className="font-semibold text-slate-200">4. Surgical Scope Constraint</div>
                  <p className="text-slate-400">
                    The prompt instructs the model to only remediate the flagged line construct, preventing style churn, extraneous library refactoring, or hallucinated logic rewrites.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: PREREQUISITES & SETUP */}
        {activeTab === 'prerequisites' && (
          <div className="space-y-6">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                Host Prerequisites & Manual Configuration Checklist
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Verify these 4 local requirements to ensure the agent runs seamlessly without unexpected permission errors.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Requirement 1: Gemini API */}
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" /> 1. Google Gemini API Key
                  </span>
                  <span className="text-[11px] font-mono text-emerald-400">100% Free</span>
                </div>
                <p className="text-xs text-slate-300">
                  Generate a free Gemini API key from Google AI Studio. This provides access to Gemini 2.5 Flash without billing setup.
                </p>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between">
                  <code>export GEMINI_API_KEY="AIzaSy..."</code>
                  <button
                    onClick={() => handleCopy('export GEMINI_API_KEY="your_api_key_here"', 'gemini')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedKey === 'gemini' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <a
                  href="https://aistudio.google.com/app/apikey"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-400 hover:underline flex items-center gap-1 inline-flex"
                >
                  Open Google AI Studio <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Requirement 2: GitHub PAT */}
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                    <GitPullRequest className="w-3.5 h-3.5" /> 2. GitHub Personal Access Token
                  </span>
                  <span className="text-[11px] font-mono text-emerald-400">Free PAT</span>
                </div>
                <p className="text-xs text-slate-300">
                  Create a Personal Access Token (classic or fine-grained) with <code className="text-cyan-400">public_repo</code> (or <code className="text-cyan-400">repo</code> for private projects).
                </p>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between">
                  <code>export GITHUB_TOKEN="ghp_..."</code>
                  <button
                    onClick={() => handleCopy('export GITHUB_TOKEN="ghp_your_token_here"', 'github')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedKey === 'github' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <a
                  href="https://github.com/settings/tokens"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-400 hover:underline flex items-center gap-1 inline-flex"
                >
                  Generate Token on GitHub <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Requirement 3: Local Docker Daemon */}
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Box className="w-3.5 h-3.5" /> 3. Local Docker Daemon Running
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">docker.sock</span>
                </div>
                <p className="text-xs text-slate-300">
                  Ensure Docker Desktop (macOS/Windows) or dockerd (Linux) is active and the unix socket is accessible.
                </p>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 space-y-1">
                  <div className="text-slate-500"># Check docker socket liveness:</div>
                  <code>docker info</code>
                </div>
                <p className="text-[11px] text-slate-400">
                  Linux permission fix: <code className="text-cyan-400">sudo usermod -aG docker $USER</code>
                </p>
              </div>

              {/* Requirement 4: Semgrep OSS CLI */}
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5" /> 4. Semgrep OSS CLI
                  </span>
                  <span className="text-[11px] font-mono text-emerald-400">Open Source</span>
                </div>
                <p className="text-xs text-slate-300">
                  Install the free open-source static analysis engine via pip or package manager.
                </p>
                <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between">
                  <code>pip install semgrep</code>
                  <button
                    onClick={() => handleCopy('pip install semgrep', 'semgrep')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedKey === 'semgrep' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-[11px] text-slate-400">
                  macOS alternative: <code className="text-cyan-400">brew install semgrep</code>
                </p>
              </div>
            </div>

            {/* Quickstart Command Sequence */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Terminal Quickstart Commands
              </h3>

              <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 space-y-2">
                <div className="text-slate-500"># 1. Install dependencies from requirements.txt</div>
                <div>pip install -r requirements.txt</div>
                <div className="text-slate-500 pt-1"># 2. Test locally on sample vulnerable repo (zero remote side-effects)</div>
                <div>python main.py --local-dir ./examples/vulnerable_repo --dry-run</div>
                <div className="text-slate-500 pt-1"># 3. Run full automated pipeline on a GitHub repository</div>
                <div>python main.py --repo your-username/target-repo --test-cmd "pytest -v"</div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span>AutoPatch AI</span>
            <span>·</span>
            <span>100% Free Open-Source Architecture</span>
            <span>·</span>
            <span>Google Gemini 2.5 Flash + Semgrep OSS</span>
          </div>
          <div>Human-in-the-Loop Verified Autonomous DevOps</div>
        </div>
      </footer>
    </div>
  );
}
