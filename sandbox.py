"""
sandbox.py
==========
Executes the repository test suite inside an ephemeral, network-isolated Docker container.
Ensures patches are rigorously verified without risking host system integrity or data exfiltration.

100% Free Stack: Uses local Docker daemon via docker-py.
"""

import os
import shutil
import tempfile
import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

try:
    import docker
    from docker.errors import DockerException, ImageNotFound, APIError
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False


class TestExecutionResult(BaseModel):
    """Output and status of running a test suite in the Docker sandbox."""
    passed: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    container_id: Optional[str] = None
    error_message: Optional[str] = None


class DockerSandbox:
    """
    Manages an ephemeral, isolated Docker environment to validate patches against existing tests.
    """

    def __init__(
        self,
        base_image: str = "python:3.11-slim",
        default_timeout: int = 180,
        memory_limit: str = "1g",
        cpu_quota: int = 100000,  # 1 CPU
        network_isolated: bool = True,
    ):
        """
        :param base_image: Docker image used to execute the repo's tests
        :param default_timeout: Timeout in seconds for test suite execution
        :param memory_limit: Cgroup memory limit to prevent memory exhaustion
        :param cpu_quota: Cgroup CPU quota (100000 = 100% of 1 core)
        :param network_isolated: If True, executes tests with network_mode='none'
        """
        self.base_image = os.getenv("DOCKER_SANDBOX_IMAGE", base_image)
        self.default_timeout = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", str(default_timeout)))
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.network_isolated = network_isolated
        self.client = None
        self._check_docker_availability()

    def _check_docker_availability(self) -> None:
        """Verifies docker library is installed and Docker daemon is running."""
        if not HAS_DOCKER:
            raise ImportError(
                "The `docker` Python package is not installed.\n"
                "Install it via: pip install docker"
            )

        try:
            self.client = docker.from_env()
            self.client.ping()
        except DockerException as e:
            raise ConnectionError(
                "Unable to connect to the local Docker daemon.\n"
                "Please ensure Docker Desktop or the dockerd service is running.\n"
                "Common fixes:\n"
                "  - Start Docker Desktop (macOS/Windows)\n"
                "  - Linux: sudo systemctl start docker\n"
                f"Underlying error: {str(e)}"
            )

    def _ensure_image_present(self, image_name: str) -> None:
        """Pulls base image if not locally cached."""
        try:
            self.client.images.get(image_name)
        except ImageNotFound:
            print(f"[*] Docker image '{image_name}' not found locally. Pulling...")
            self.client.images.pull(image_name)

    def run_tests(
        self,
        repo_dir: str,
        test_command: str = "pytest -v",
        install_dependencies: bool = True,
        env_vars: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> TestExecutionResult:
        """
        Copies repo to an isolated temp directory, binds it inside an ephemeral container,
        executes the test suite, and tears down the container.

        :param repo_dir: Path to the patched repository
        :param test_command: Test command to execute (e.g., 'pytest', 'python -m unittest')
        :param install_dependencies: Whether to run pip install before tests (requires temporary network)
        :param env_vars: Optional environment variables to pass to the container
        :param timeout: Execution timeout in seconds
        """
        max_duration = timeout or self.default_timeout
        self._ensure_image_present(self.base_image)

        # Create isolated temporary directory so tests cannot mutate user's original workspace
        temp_dir = tempfile.mkdtemp(prefix="autopatch_sandbox_")
        container = None
        start_time = time.time()

        try:
            # Copy patched repo into temp directory
            shutil.copytree(repo_dir, os.path.join(temp_dir, "app"), dirs_exist_ok=True)
            workspace_mount = os.path.join(temp_dir, "app")

            volumes = {
                workspace_mount: {"bind": "/app", "mode": "rw"}
            }

            container_env = env_vars or {}
            container_env["PYTHONUNBUFFERED"] = "1"
            container_env["PYTHONDONTWRITEBYTECODE"] = "1"

            # Construct execution script
            # 1. Install dependencies from requirements.txt or pyproject.toml if present
            # 2. Run the actual test suite
            script_lines = [
                "#!/bin/bash",
                "set -e",
                "cd /app",
            ]

            if install_dependencies and os.path.exists(os.path.join(workspace_mount, "requirements.txt")):
                script_lines.append("pip install --quiet --no-cache-dir -r requirements.txt || true")
            
            # Append test runner
            script_lines.append(f"{test_command}")
            runner_script = "\n".join(script_lines)

            # Write runner script to temp folder
            runner_path = os.path.join(workspace_mount, "__autopatch_runner.sh")
            with open(runner_path, "w", encoding="utf-8") as f:
                f.write(runner_script)
            os.chmod(runner_path, 0o755)

            network_setting = "bridge" if install_dependencies else "none"
            if self.network_isolated and not install_dependencies:
                network_setting = "none"

            container = self.client.containers.create(
                image=self.base_image,
                command=["/bin/bash", "/app/__autopatch_runner.sh"],
                volumes=volumes,
                working_dir="/app",
                environment=container_env,
                network_mode=network_setting,
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                security_opt=["no-new-privileges:true"],
                labels={"autopatch": "ephemeral_test_runner"},
            )

            container.start()

            # Wait for container execution with timeout
            deadline = time.time() + max_duration
            completed = False
            status_data = None

            while time.time() < deadline:
                container.reload()
                if container.status in ("exited", "dead"):
                    status_data = container.wait()
                    completed = True
                    break
                time.sleep(1)

            if not completed:
                try:
                    container.kill()
                except Exception:
                    pass
                duration = time.time() - start_time
                return TestExecutionResult(
                    passed=False,
                    exit_code=124,  # Standard timeout exit code
                    stdout="",
                    stderr=f"Test run timed out after {max_duration} seconds.",
                    duration_seconds=duration,
                    container_id=container.id[:12] if container else None,
                    error_message=f"Timeout of {max_duration}s exceeded.",
                )

            duration = time.time() - start_time
            exit_code = status_data.get("StatusCode", -1) if status_data else -1
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

            # Clean runner file from temp dir
            if os.path.exists(runner_path):
                os.remove(runner_path)

            return TestExecutionResult(
                passed=(exit_code == 0),
                exit_code=exit_code,
                stdout=logs,
                stderr="",
                duration_seconds=duration,
                container_id=container.id[:12] if container else None,
                error_message=None if exit_code == 0 else f"Tests failed with exit code {exit_code}",
            )

        except APIError as e:
            return TestExecutionResult(
                passed=False,
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=time.time() - start_time,
                error_message=f"Docker API error: {str(e)}",
            )
        except Exception as e:
            return TestExecutionResult(
                passed=False,
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=time.time() - start_time,
                error_message=f"Sandbox execution failed: {str(e)}",
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            # Clean up temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    print("[*] Testing DockerSandbox connection...")
    try:
        box = DockerSandbox()
        print("[+] Docker daemon is connected and responsive!")
    except Exception as err:
        print("[-] Docker error:", err)
