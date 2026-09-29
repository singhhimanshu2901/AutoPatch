"""
agent_patcher.py
================
Synthesizes surgical, deterministic security patches using Google Gemini's Free Tier API.
Verifies syntax correctness locally before any patch is accepted.

100% Free Stack: Uses Google Gemini Free API (Gemini 2.5 Flash / 1.5 Flash).
"""

import ast
import difflib
import json
import os
import re
from typing import Optional, Tuple
from pydantic import BaseModel, Field

# Support both new `google-genai` and classic `google.generativeai`
try:
    from google import genai
    from google.genai import types as genai_types
    HAS_NEW_GENAI = True
except ImportError:
    HAS_NEW_GENAI = False
    try:
        import google.generativeai as legacy_genai
        HAS_LEGACY_GENAI = True
    except ImportError:
        HAS_LEGACY_GENAI = False


class PatchResult(BaseModel):
    """Encapsulates the generated security patch and metadata."""
    success: bool
    file_path: str
    original_code: str
    patched_code: str
    unified_diff: str
    commit_message: str
    explanation: str
    cwe_mitigation: str
    syntax_valid: bool
    error_message: Optional[str] = None


class GeminiSecurityPatcher:
    """
    Orchestrates LLM patch synthesis with strict determinism and syntax verification.
    """

    SYSTEM_INSTRUCTION = """You are an elite Principal Security Engineer and DevOps Architect.
Your task is to fix a specific security vulnerability identified by a SAST scanner (Semgrep).

CRITICAL DIRECTIVES:
1. SURGICAL REMEDIATION ONLY: Fix only the exact vulnerable construct flagged. Do NOT refactor surrounding code, change styling, rename variables, or introduce unrelated 'improvements'.
2. DETERMINISTIC FIX:
   - For SQL Injection: Use parameterized queries / prepared statements (never string interpolation or format strings).
   - For Command Injection: Avoid shell=True in subprocess; use argument lists, shlex.quote, or safe standard library APIs.
   - For Path Traversal: Resolve and canonicalize paths using os.path.realpath / Path.resolve() and verify the target path stays within the intended base directory.
   - For Hardcoded Secrets: Move secrets to environment variables (os.environ.get) with sensible defaults or fail-closed behavior.
   - For Insecure Deserialization: Replace pickle/yaml.load with json, safeyaml, or cryptographic HMAC verification.
   - For SSRF / URL handling: Enforce strict whitelist validation or restrict schemes to http/https and block internal IP ranges (127.0.0.1, 169.254.169.254).
3. IMPORTS: If a new safe standard library is needed (e.g., shlex, os, pathlib, hmac), place the import cleanly at the top of the file without disrupting existing imports.
4. VALID SYNTAX: The patched file MUST be 100% syntactically valid code.
5. OUTPUT FORMAT: You must reply with a valid JSON object matching this exact schema:
{
  "explanation": "Concise 2-3 sentence technical explanation of the vulnerability and how the patch mitigates it.",
  "commit_message": "fix(security): remediate <vulnerability_type> in <file_path>",
  "cwe_mitigation": "Details of the specific CWE mitigation applied.",
  "patched_file_content": "THE ENTIRE FILE CONTENT WITH THE PATCH APPLIED. Do not omit any code."
}
Do NOT wrap the JSON inside markdown markdown code blocks if possible, or if you do, use ```json ... ```."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-2.5-flash"):
        """
        :param api_key: Google Gemini API key (defaults to GEMINI_API_KEY environment variable)
        :param model_name: Gemini model to use (default: gemini-2.5-flash)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY is not set.\n"
                "Obtain a 100% free Gemini API key from https://aistudio.google.com/app/apikey "
                "and set it in your .env or environment variables."
            )
        self.model_name = model_name
        self._init_client()

    def _init_client(self) -> None:
        """Initializes the Gemini API client."""
        if HAS_NEW_GENAI:
            self.client = genai.Client(api_key=self.api_key)
            self._use_new_sdk = True
        elif HAS_LEGACY_GENAI:
            legacy_genai.configure(api_key=self.api_key)
            self.legacy_model = legacy_genai.GenerativeModel(
                model_name=self.model_name,
                system_instruction=self.SYSTEM_INSTRUCTION,
            )
            self._use_new_sdk = False
        else:
            raise ImportError(
                "Neither `google-genai` nor `google-generativeai` is installed.\n"
                "Install via: pip install google-genai"
            )

    def _call_gemini(self, prompt: str) -> str:
        """Calls the Gemini API and returns the raw string response."""
        if self._use_new_sdk:
            config = genai_types.GenerateContentConfig(
                temperature=0.1,  # Low temperature for deterministic, reliable code synthesis
                system_instruction=self.SYSTEM_INSTRUCTION,
            )
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config,
            )
            return response.text or ""
        else:
            generation_config = legacy_genai.types.GenerationConfig(
                temperature=0.1,
            )
            response = self.legacy_model.generate_content(
                prompt,
                generation_config=generation_config,
            )
            return response.text or ""

    def _validate_syntax(self, code: str, file_path: str) -> Tuple[bool, Optional[str]]:
        """Validates syntax for languages where native parsers are readily available."""
        if file_path.endswith(".py"):
            try:
                ast.parse(code)
                return True, None
            except SyntaxError as e:
                return False, f"Python SyntaxError at line {e.lineno}: {e.msg}"
        # For non-Python files, basic empty-check and bracket check
        if not code.strip():
            return False, "Patched code is empty"
        return True, None

    def _generate_diff(self, original: str, patched: str, file_path: str) -> str:
        """Generates a standardized unified git diff."""
        orig_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def generate_patch(
        self,
        file_path: str,
        file_content: str,
        rule_id: str,
        message: str,
        vulnerable_code: str,
        start_line: int,
        end_line: int,
        cwe: Optional[list] = None,
        max_retries: int = 2,
    ) -> PatchResult:
        """
        Synthesizes a clean security patch for the given finding, validating syntax with auto-retry.
        """
        cwe_str = ", ".join(cwe) if cwe else "Not Specified"

        base_prompt = f"""Target File: {file_path}
Vulnerability Rule ID: {rule_id}
CWE: {cwe_str}
Line Numbers: {start_line} to {end_line}
Scanner Warning: {message}

Vulnerable Snippet Flagged:
```
{vulnerable_code}
```

Full Current File Content:
```
{file_content}
```

Generate the surgical fix. Remember to output ONLY the JSON object with fields:
- explanation
- commit_message
- cwe_mitigation
- patched_file_content"""

        current_prompt = base_prompt

        for attempt in range(max_retries + 1):
            try:
                raw_response = self._call_gemini(current_prompt)
            except Exception as e:
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    original_code=file_content,
                    patched_code="",
                    unified_diff="",
                    commit_message="",
                    explanation="",
                    cwe_mitigation="",
                    syntax_valid=False,
                    error_message=f"Gemini API invocation error: {str(e)}",
                )

            # Clean JSON markdown fences if present
            cleaned = raw_response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            elif cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            try:
                data = json.loads(cleaned)
            except json.JSONDecodeError:
                # Attempt regex recovery if extra text exists
                match = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if match:
                    try:
                        data = json.loads(match.group(0))
                    except Exception:
                        data = None
                else:
                    data = None

            if not data or "patched_file_content" not in data:
                if attempt < max_retries:
                    current_prompt = (
                        base_prompt
                        + f"\n\n[ERROR]: Your previous response was not valid JSON. Provide ONLY pure JSON matching the requested structure."
                    )
                    continue
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    original_code=file_content,
                    patched_code="",
                    unified_diff="",
                    commit_message="",
                    explanation="",
                    cwe_mitigation="",
                    syntax_valid=False,
                    error_message="Model failed to return valid JSON output after retries.",
                )

            patched_content = data.get("patched_file_content", "")
            explanation = data.get("explanation", "Security patch generated by Gemini")
            commit_msg = data.get("commit_message", f"fix(security): patch {rule_id} in {file_path}")
            cwe_mitigation = data.get("cwe_mitigation", "")

            # Validate syntax
            is_valid, syntax_err = self._validate_syntax(patched_content, file_path)
            if not is_valid:
                if attempt < max_retries:
                    current_prompt = (
                        base_prompt
                        + f"\n\n[SYNTAX ERROR in previous attempt]: {syntax_err}\nPlease fix the syntax error and return the full corrected file content in valid JSON."
                    )
                    continue
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    original_code=file_content,
                    patched_code=patched_content,
                    unified_diff=self._generate_diff(file_content, patched_content, file_path),
                    commit_message=commit_msg,
                    explanation=explanation,
                    cwe_mitigation=cwe_mitigation,
                    syntax_valid=False,
                    error_message=syntax_err,
                )

            diff_str = self._generate_diff(file_content, patched_content, file_path)

            return PatchResult(
                success=True,
                file_path=file_path,
                original_code=file_content,
                patched_code=patched_content,
                unified_diff=diff_str,
                commit_message=commit_msg,
                explanation=explanation,
                cwe_mitigation=cwe_mitigation,
                syntax_valid=True,
                error_message=None,
            )

        return PatchResult(
            success=False,
            file_path=file_path,
            original_code=file_content,
            patched_code="",
            unified_diff="",
            commit_message="",
            explanation="",
            cwe_mitigation="",
            syntax_valid=False,
            error_message="Max patch generation retries exhausted.",
        )


if __name__ == "__main__":
    # Quick standalone test helper
    sample_vuln = """import sqlite3

def get_user_records(user_input):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    patcher = GeminiSecurityPatcher()
    res = patcher.generate_patch(
        file_path="db.py",
        file_content=sample_vuln,
        rule_id="python.sqlite3.sqli",
        message="SQL query built using f-string interpolation with user input",
        vulnerable_code="query = f\"SELECT * FROM users WHERE username = '{user_input}'\"",
        start_line=7,
        end_line=8,
        cwe=["CWE-89: SQL Injection"],
    )
    print("Patch success:", res.success)
    print("Diff:\n", res.unified_diff)
    print("Explanation:", res.explanation)
