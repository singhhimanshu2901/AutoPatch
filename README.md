# 🛡️ AutoPatch AI: Autonomous Security Remediation Agent

An autonomous, **100% free open-source AI agent** that scans GitHub repositories for security vulnerabilities, synthesizes deterministic surgical patches, validates them inside ephemeral network-isolated Docker containers, and opens Pull Requests with an interactive Human-in-the-Loop review gate.

---

## 🏗️ 100% Free Architecture Stack

| Component | Technology | Cost | Description |
| :--- | :--- | :--- | :--- |
| **LLM Engine** | **Google Gemini 2.5 Flash** | **$0.00 / Free Tier** | High-fidelity, deterministic code patch synthesis via `google-genai` SDK |
| **SAST Scanner** | **Semgrep OSS CLI** | **$0.00 / Free Open-Source** | Local offline static analysis with community rule packs (`p/security-audit`, `p/owasp-top-ten`) |
| **Sandbox Execution** | **Local Docker Daemon** | **$0.00 / Local Native** | Network-isolated ephemeral test execution via `docker-py` with memory/CPU quotas |
| **GitHub Automation** | **PyGithub + GitPython** | **$0.00 / Free PAT** | Automates forking upstream repos, branch creation, commit staging, and PR submission |
| **Terminal & HITL Gate** | **Rich Terminal UI** | **$0.00 / Free** | Monokai syntax-highlighted unified diffs with interactive approval prompts |

---

## 📋 Mandatory Prerequisites & Manual Settings

Before running the agent, configure the following four components on your host machine:

### 1. Google Gemini API Key (Free)
1. Navigate to [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Click **Create API Key** (eligible for the 100% free rate-limited tier, ~15 RPM / 1M TPM).
3. Set in your `.env` or shell:
   ```bash
   export GEMINI_API_KEY="your_api_key_here"
   ```

### 2. GitHub Personal Access Token (Free PAT)
1. Go to **GitHub Settings** -> **Developer Settings** -> **Personal Access Tokens** -> **Tokens (classic)** (or Fine-grained tokens).
2. Click **Generate new token**.
3. Select the following scopes:
   - `public_repo` (if scanning open-source repos) or `repo` (if scanning private repos).
   - `workflow` (optional, if modifying GitHub Actions).
4. Export the token:
   ```bash
   export GITHUB_TOKEN="ghp_your_github_token_here"
   ```

### 3. Local Docker Daemon (Docker Desktop or dockerd)
The agent spins up ephemeral Docker containers to verify that your repository's existing test suite passes before proposing a PR.
- **macOS / Windows**: Start **Docker Desktop**. In Settings -> Advanced, ensure the default Docker socket `/var/run/docker.sock` is enabled.
- **Linux**: Verify the Docker daemon is active:
  ```bash
  sudo systemctl start docker
  sudo usermod -aG docker $USER  # to run without sudo
  ```

### 4. Semgrep OSS CLI
Install the free open-source Semgrep CLI on your machine:
```bash
pip install semgrep
# or on macOS via Homebrew:
brew install semgrep
```

---

## 🚀 Quickstart Installation

```bash
# 1. Clone this repository
git clone https://github.com/your-username/autopatch-ai.git
cd autopatch-ai

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install free dependencies
pip install -r requirements.txt

# 4. Copy and fill environment template
cp .env.example .env
# Edit .env and paste your GEMINI_API_KEY and GITHUB_TOKEN
```

---

## 💻 Running the Agent

### A. Dry-Run / Local Verification (Zero Remote Writes)
Run the scanner, patcher, and Docker sandbox on a local directory without touching GitHub:
```bash
python main.py --local-dir ./examples/vulnerable_repo --dry-run
```

### B. Full Autonomous Pipeline with Human-in-the-Loop Approval Gate
Target any public GitHub repository (e.g. `octocat/Hello-World` or your own test fork):
```bash
python main.py --repo your-username/my-sample-repo --test-cmd "pytest -v"
```

### C. Available CLI Arguments
- `--repo <owner/repo>`: Target repository on GitHub.
- `--local-dir <path>`: Local repository directory.
- `--test-cmd <cmd>`: Command executed in Docker to verify test suite (default: `pytest -v`).
- `--rules <ruleset>`: Semgrep rule pack (default: `p/security-audit`, options: `p/owasp-top-ten`, `p/python`, `p/ci`).
- `--dry-run`: Runs scanning, patch generation, and Docker sandbox tests, displays diffs, but does not push branches or open PRs.
- `--auto-approve`: Bypasses interactive terminal prompt (use with caution in automated CI).

---

## 🔒 Safety & Anti-Spam Architecture

1. **Pre-Flight Validation**: Verifies all API credentials, Docker socket liveness, and SAST scanner availability before cloning or scanning.
2. **Ephemeral Network-Isolated Sandbox**: Tests are executed with `network_mode='none'`, `no-new-privileges:true`, and strict CPU/Memory cgroups to protect the host against malicious code execution.
3. **Deterministic Prompting**: Enforces strict AST syntax parsing and surgical changes only; forbids unwanted refactoring or styling churn.
4. **Mandatory Human-in-the-Loop Review**: Every synthesized patch is displayed with unified syntax diffs and requires explicit console confirmation (`approve`, `reject`, `skip`) before any git push.
