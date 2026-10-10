#!/usr/bin/env python3
"""Git Security Sentinel - Deterministic Git diff security scanner.

Zero third-party dependencies: uses Python standard library only.
Scans Git diffs (staged, unstaged, all, branch-comparison, or file) for exposed
credentials, dangerous code execution patterns, hardcoded service endpoints,
and root open-source license presence.

All detected credentials and sensitive patterns are safely redacted before
appearing in terminal output, JSON reports, or sanitized diff patches.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Pattern, Tuple

__version__ = "1.0.0"
SCANNER_NAME = "git-security-sentinel"

# Standard license file candidates in repository root
ACCEPTED_LICENSE_NAMES = (
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
)

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    message: str
    evidence: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


@dataclass
class LicenseStatus:
    root_license_present: bool
    license_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    scanner: str = SCANNER_NAME
    version: str = __version__
    status: str = "completed"
    scan_mode: str = "all"
    findings: List[Finding] = field(default_factory=list)
    license: LicenseStatus = field(default_factory=lambda: LicenseStatus(False))
    summary: ScanSummary = field(default_factory=ScanSummary)
    errors: List[str] = field(default_factory=list)
    ai_review: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "scanner": self.scanner,
            "version": self.version,
            "status": self.status,
            "scan_mode": self.scan_mode,
            "findings": [f.to_dict() for f in self.findings],
            "license": self.license.to_dict(),
            "summary": self.summary.to_dict(),
            "errors": self.errors,
        }
        if self.ai_review is not None:
            data["ai_review"] = self.ai_review
        return data


# ============================================================================
# Safe Redaction Helpers
# ============================================================================

def redact_sensitive_string(raw: str, prefix_len: int = 4, suffix_len: int = 2) -> str:
    """Mask the middle of a credential string with asterisks.
    
    If the string is short, mask entirely. Never returns raw secret.
    """
    clean = raw.strip("\"' ")
    if len(clean) <= (prefix_len + suffix_len + 3):
        return "[REDACTED]"
    prefix = clean[:prefix_len]
    suffix = clean[-suffix_len:] if suffix_len > 0 else ""
    masked_len = max(len(clean) - prefix_len - suffix_len, 4)
    return f"{prefix}{'*' * min(masked_len, 24)}{suffix}"


def sanitize_line_content(line: str, rules: List[Rule]) -> str:
    """Replace all detected secret patterns on a line with masked versions."""
    sanitized = line
    for rule in rules:
        if rule.category != "secrets":
            continue
        for match in rule.pattern.finditer(sanitized):
            if rule.validator and not rule.validator(match, sanitized):
                continue
            if "value" in match.groupdict() and match.group("value"):
                secret_span = match.group("value")
            else:
                secret_span = match.group(0)
            redacted = redact_sensitive_string(secret_span)
            sanitized = sanitized.replace(secret_span, redacted)
    return sanitized


# ============================================================================
# Detection Rule Engine
# ============================================================================

@dataclass
class Rule:
    rule_id: str
    category: str
    severity: str
    confidence: str
    message: str
    recommendation: str
    pattern: Pattern[str]
    # Optional validator/filter function returning True if match is a genuine finding
    validator: Optional[Any] = None


# Generic secret false positive filters
SAFE_VALUE_PATTERNS = [
    re.compile(r"^[\s\"']*(true|false|null|none|undefined|test|example|dummy|placeholder|sample|changeme|todo|fixme)[\s\"']*$", re.IGNORECASE),
    re.compile(r"^[\s\"']*\$\{[^}]+\}[\s\"']*$"),  # Shell/JS template: ${VAR}
    re.compile(r"^[\s\"']*%\{[^}]+\}[\s\"']*$"),
    re.compile(r"^[\s\"']*<[^>]+>[\s\"']*$"),       # <PLACEHOLDER>
    re.compile(r"^[\s\"']*\[[^\]]+\][\s\"']*$"),   # [PLACEHOLDER]
    re.compile(r"process\.env\.", re.IGNORECASE),
    re.compile(r"os\.(environ|getenv)", re.IGNORECASE),
    re.compile(r"System\.getenv", re.IGNORECASE),
    re.compile(r"env::var", re.IGNORECASE),
]


def _validate_generic_credential(match: re.Match[str], line: str) -> bool:
    """Filter out benign assignments, empty strings, and environment variable references."""
    val = match.group("value") if "value" in match.groupdict() else match.group(0)
    cleaned = val.strip("\"' \t,;")
    if not cleaned or len(cleaned) < 8:
        return False
    for safe in SAFE_VALUE_PATTERNS:
        if safe.search(cleaned) or safe.search(line):
            return False
    # If the value is pure whitespace or common variable name
    if cleaned.lower() in {"password", "secret", "token", "mysecret", "admin"}:
        return False
    return True


RULES: List[Rule] = [
    Rule(
        rule_id="secret.aws_access_key",
        category="secrets",
        severity="high",
        confidence="high",
        message="Potential AWS Access Key ID detected.",
        recommendation="Store AWS credentials in IAM roles or environment variables. Revoke key if exposed.",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    Rule(
        rule_id="secret.aws_secret_key",
        category="secrets",
        severity="high",
        confidence="medium",
        message="Potential AWS Secret Access Key assignment detected.",
        recommendation="Use AWS Secrets Manager or environment variables. Rotate key if exposed.",
        pattern=re.compile(
            r"""(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*["'](?P<value>[0-9a-zA-Z/+]{40})["']"""
        ),
        validator=_validate_generic_credential,
    ),
    Rule(
        rule_id="secret.github_pat_classic",
        category="secrets",
        severity="high",
        confidence="high",
        message="GitHub personal access token (classic) detected.",
        recommendation="Revoke this personal access token in GitHub Developer Settings and generate a new one.",
        pattern=re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    ),
    Rule(
        rule_id="secret.github_pat_fine_grained",
        category="secrets",
        severity="high",
        confidence="high",
        message="GitHub fine-grained personal access token detected.",
        recommendation="Revoke this fine-grained personal access token in GitHub Developer Settings immediately.",
        pattern=re.compile(r"\b(github_pat_[0-9a-zA-Z_]{82})\b"),
    ),
    Rule(
        rule_id="secret.github_token_scoped",
        category="secrets",
        severity="high",
        confidence="high",
        message="GitHub scoped OAuth, user-to-server, or server token detected.",
        recommendation="Revoke this GitHub credential immediately and rotate any associated integration keys.",
        pattern=re.compile(r"\b(gh[ours]_[0-9a-zA-Z]{36,255})\b"),
    ),
    Rule(
        rule_id="secret.private_key",
        category="secrets",
        severity="critical",
        confidence="high",
        message="Private cryptographic key header detected.",
        recommendation="Never commit private keys to version control. Revoke and generate a new key pair.",
        pattern=re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----"
        ),
    ),
    Rule(
        rule_id="secret.slack_token",
        category="secrets",
        severity="high",
        confidence="high",
        message="Slack API token detected.",
        recommendation="Revoke this token in your Slack App configuration and use environment variables.",
        pattern=re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    ),
    Rule(
        rule_id="secret.generic_credential",
        category="secrets",
        severity="high",
        confidence="medium",
        message="Generic hardcoded secret, token, or password assignment detected.",
        recommendation="Move sensitive values to a secure .env file or secrets vault loaded via environment variables.",
        pattern=re.compile(
            r"""(?i)\b(?:[a-z0-9_-]*(?:api_key|apikey|secret_key|secret|password|passwd|auth_token|access_token|client_secret))\s*[:=]\s*["'](?P<value>[^"' \t\r\n]{8,128})["']"""
        ),
        validator=_validate_generic_credential,
    ),
    Rule(
        rule_id="code.dangerous_eval",
        category="risky_code",
        severity="medium",
        confidence="medium",
        message="Potentially unsafe dynamic code evaluation (eval/exec) detected.",
        recommendation="Avoid eval() or exec() with untrusted input; use structured parsing like json.loads() or ast.literal_eval().",
        pattern=re.compile(r"\b(?:eval|exec)\s*\([^)]*\)"),
    ),
    Rule(
        rule_id="config.hardcoded_localhost",
        category="configuration",
        severity="low",
        confidence="low",
        message="Hardcoded localhost or loopback endpoint detected.",
        recommendation="Extract local host/port into configurable environment variables for production readiness.",
        pattern=re.compile(r"""https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?"""),
    ),
]


# ============================================================================
# Git Diff Parser
# ============================================================================

@dataclass
class DiffHunkLine:
    file_path: str
    line_number: int
    content: str  # Added line content without leading '+'


def parse_unified_diff(diff_text: str) -> List[DiffHunkLine]:
    """Parse unified git diff output into a list of added lines with line numbers.
    
    Ignores diff headers, hunk headers, deleted lines, and file mode lines.
    Tracks line numbers for added lines accurately according to hunk headers @@ -a,b +c,d @@.
    """
    added_lines: List[DiffHunkLine] = []
    current_file: Optional[str] = None
    current_target_line = 0

    for line in diff_text.splitlines():
        # Track file name from diff headers
        # e.g.: "diff --git a/file.py b/file.py"
        if line.startswith("diff --git "):
            current_file = None
            continue

        # Target file header: "+++ b/path/to/file.py" or "+++ /dev/null"
        if line.startswith("+++ "):
            raw_path = line[4:].strip()
            if raw_path == "/dev/null":
                current_file = None
            elif raw_path.startswith("b/"):
                current_file = raw_path[2:]
            else:
                current_file = raw_path
            continue

        # Ignore other headers
        if line.startswith("--- ") or line.startswith("index ") or line.startswith("new file ") or line.startswith("deleted file "):
            continue

        # Hunk header: @@ -orig_start,orig_count +target_start,target_count @@
        if line.startswith("@@ "):
            match = re.search(r"@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,[0-9]+)?\s+@@", line)
            if match:
                current_target_line = int(match.group(1))
            continue

        if current_file is None:
            continue

        # Added line
        if line.startswith("+"):
            content = line[1:]
            added_lines.append(
                DiffHunkLine(
                    file_path=current_file,
                    line_number=current_target_line,
                    content=content,
                )
            )
            current_target_line += 1
        elif line.startswith("-"):
            # Deleted line: does not increment target file line number
            continue
        else:
            # Context line (space prefix or empty)
            current_target_line += 1

    return added_lines


# ============================================================================
# Git Subprocess Utilities
# ============================================================================

def run_git_command(args: List[str], cwd: Optional[Path] = None, timeout: int = 30) -> Tuple[int, str, str]:
    """Run a Git command safely without shell=True."""
    cmd = ["git"] + args
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "Git executable was not found on system PATH."
    except subprocess.TimeoutExpired:
        return 124, "", f"Git command timed out after {timeout} seconds."
    except Exception as exc:
        return 1, "", str(exc)


def get_git_diff(
    mode: str,
    base: Optional[str] = None,
    cwd: Optional[Path] = None,
) -> Tuple[str, List[str]]:
    """Retrieve Git diff output according to requested mode.
    
    Modes:
    - staged: changes staged in index
    - unstaged: unstaged working tree changes
    - all: staged + unstaged changes
    - base: merge-base diff against a specified base branch
    """
    errors: List[str] = []

    # Check if inside git work tree
    rc, stdout, stderr = run_git_command(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
    if rc != 0:
        errors.append(f"Not a git repository (or any parent up to mount point): {stderr.strip()}")
        return "", errors

    # Check if repo has at least one commit
    rc_rev, _, _ = run_git_command(["rev-parse", "--verify", "HEAD"], cwd=cwd)
    has_commits = (rc_rev == 0)

    if mode == "staged":
        git_args = ["diff", "--staged", "--no-ext-diff", "--no-color"]
        rc, stdout, stderr = run_git_command(git_args, cwd=cwd)
        if rc != 0:
            errors.append(f"Failed to get staged diff: {stderr.strip()}")
        return stdout, errors

    if mode == "unstaged":
        git_args = ["diff", "--no-ext-diff", "--no-color"]
        rc, stdout, stderr = run_git_command(git_args, cwd=cwd)
        if rc != 0:
            errors.append(f"Failed to get unstaged diff: {stderr.strip()}")
        return stdout, errors

    if mode == "all":
        if has_commits:
            git_args = ["diff", "HEAD", "--no-ext-diff", "--no-color"]
            rc, stdout, stderr = run_git_command(git_args, cwd=cwd)
            if rc != 0:
                errors.append(f"Failed to get all changes diff: {stderr.strip()}")
            return stdout, errors
        else:
            # Initial commit state: combine staged and unstaged
            parts = []
            rc1, out1, err1 = run_git_command(["diff", "--staged", "--no-ext-diff", "--no-color"], cwd=cwd)
            if rc1 == 0:
                parts.append(out1)
            else:
                errors.append(f"Failed to inspect staged: {err1.strip()}")
            rc2, out2, err2 = run_git_command(["diff", "--no-ext-diff", "--no-color"], cwd=cwd)
            if rc2 == 0:
                parts.append(out2)
            else:
                errors.append(f"Failed to inspect unstaged: {err2.strip()}")
            return "\n".join(parts), errors

    if mode == "base":
        if not base:
            errors.append("Base branch must be specified when using --base mode.")
            return "", errors

        # Determine merge base
        rc_mb, mb_out, mb_err = run_git_command(["merge-base", base, "HEAD"], cwd=cwd)
        if rc_mb != 0:
            errors.append(f"Failed to determine merge-base with '{base}': {mb_err.strip()}")
            return "", errors

        merge_base = mb_out.strip()
        git_args = ["diff", f"{merge_base}..HEAD", "--no-ext-diff", "--no-color"]
        rc, stdout, stderr = run_git_command(git_args, cwd=cwd)
        if rc != 0:
            errors.append(f"Failed to get diff against base '{base}': {stderr.strip()}")
        return stdout, errors

    errors.append(f"Unknown scan mode: {mode}")
    return "", errors


# ============================================================================
# License Checker
# ============================================================================

def check_root_license(repo_root: Path) -> LicenseStatus:
    """Check for existence of standard open-source license files in repo root."""
    try:
        for candidate in ACCEPTED_LICENSE_NAMES:
            candidate_path = repo_root / candidate
            if candidate_path.is_file():
                return LicenseStatus(root_license_present=True, license_file=candidate)
    except Exception:
        pass
    return LicenseStatus(root_license_present=False, license_file=None)


# ============================================================================
# Core Scanner Logic
# ============================================================================

def is_path_excluded(file_path: str, exclude_patterns: List[str]) -> bool:
    """Check if file_path matches any of the given glob patterns."""
    norm_path = file_path.replace("\\", "/")
    for pattern in exclude_patterns:
        norm_pat = pattern.replace("\\", "/").strip()
        if not norm_pat:
            continue
        if fnmatch.fnmatch(norm_path, norm_pat):
            return True
        if fnmatch.fnmatch(norm_path, f"*/{norm_pat}") or fnmatch.fnmatch(norm_path, f"{norm_pat}/*"):
            return True
        if fnmatch.fnmatch(Path(norm_path).name, norm_pat):
            return True
    return False


def scan_added_lines(
    lines: List[DiffHunkLine],
    exclude_patterns: Optional[List[str]] = None,
) -> List[Finding]:
    """Execute all security rules against parsed added diff lines."""
    findings: List[Finding] = []
    seen_keys = set()
    patterns = exclude_patterns or []

    for item in lines:
        if patterns and is_path_excluded(item.file_path, patterns):
            continue

        for rule in RULES:
            matches = list(rule.pattern.finditer(item.content))
            for match in matches:
                if rule.validator and not rule.validator(match, item.content):
                    continue

                # Safely redact matched evidence
                matched_raw = match.group("value") if ("value" in match.groupdict() and match.group("value")) else match.group(0)
                if rule.category == "secrets":
                    evidence = redact_sensitive_string(matched_raw)
                else:
                    evidence = matched_raw.strip()
                    if len(evidence) > 60:
                        evidence = evidence[:57] + "..."

                dedup_key = (rule.rule_id, item.file_path, item.line_number)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                finding = Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    file=item.file_path,
                    line=item.line_number,
                    message=rule.message,
                    evidence=evidence,
                    recommendation=rule.recommendation,
                )
                findings.append(finding)

    return findings


def calculate_summary(findings: List[Finding]) -> ScanSummary:
    """Calculate summary counts grouped by severity."""
    summary = ScanSummary(total=len(findings))
    for f in findings:
        sev = f.severity.lower()
        if sev == "critical":
            summary.critical += 1
        elif sev == "high":
            summary.high += 1
        elif sev == "medium":
            summary.medium += 1
        elif sev == "low":
            summary.low += 1
        elif sev == "info":
            summary.info += 1
    return summary


def generate_sanitized_patch(diff_text: str) -> str:
    """Generate a sanitized version of the diff patch where secrets are redacted."""
    sanitized_lines = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            clean = sanitize_line_content(content, RULES)
            sanitized_lines.append("+" + clean)
        else:
            sanitized_lines.append(line)
    return "\n".join(sanitized_lines) + "\n"


# ============================================================================
# CLI Output & Formatting
# ============================================================================

def print_text_report(report: ScanReport, out_stream=sys.stdout) -> None:
    """Render a clean, human-readable terminal summary."""
    print("=" * 70, file=out_stream)
    print(f"  GIT SECURITY SENTINEL - SCAN REPORT (v{report.version})", file=out_stream)
    print("=" * 70, file=out_stream)
    print(f"Status      : {report.status.upper()}", file=out_stream)
    print(f"Scan Mode   : {report.scan_mode}", file=out_stream)
    
    if report.license.root_license_present:
        print(f"Root License: Found ({report.license.license_file})", file=out_stream)
    else:
        print("Root License: MISSING (No LICENSE or COPYING file found in root)", file=out_stream)

    print("-" * 70, file=out_stream)
    print(
        f"Summary     : Total: {report.summary.total} | "
        f"Critical: {report.summary.critical} | "
        f"High: {report.summary.high} | "
        f"Medium: {report.summary.medium} | "
        f"Low: {report.summary.low}",
        file=out_stream,
    )
    print("-" * 70, file=out_stream)

    if report.errors:
        print("\n[!] Execution Errors / Warnings:", file=out_stream)
        for err in report.errors:
            print(f"  - {err}", file=out_stream)

    if not report.findings:
        print("\n[+] No security issues detected in scanned changes.", file=out_stream)
    else:
        print("\n[!] Findings Detected:\n", file=out_stream)
        for idx, f in enumerate(report.findings, start=1):
            sev_badge = f"[{f.severity.upper()}]"
            print(f"{idx}. {sev_badge} {f.rule_id} ({f.category})", file=out_stream)
            print(f"   Location : {f.file}:{f.line}", file=out_stream)
            print(f"   Message  : {f.message}", file=out_stream)
            print(f"   Evidence : {f.evidence}", file=out_stream)
            print(f"   Remedy   : {f.recommendation}", file=out_stream)
            print("", file=out_stream)

    print("=" * 70, file=out_stream)

    if report.ai_review:
        print("", file=out_stream)
        try:
            from ai_review import print_ai_review
            print_ai_review(report.ai_review, out_stream=out_stream)
        except ImportError:
            try:
                from scripts.ai_review import print_ai_review
                print_ai_review(report.ai_review, out_stream=out_stream)
            except Exception:
                pass


# ============================================================================
# Main Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scan_diff.py",
        description="Deterministic Git diff security scanner (Python standard library only).",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--staged",
        action="store_true",
        help="Scan git staged changes only.",
    )
    mode_group.add_argument(
        "--unstaged",
        action="store_true",
        help="Scan git unstaged changes only.",
    )
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Scan both staged and unstaged local changes (default).",
    )
    mode_group.add_argument(
        "--base",
        metavar="BRANCH",
        help="Scan diff between merge-base of BRANCH and current HEAD.",
    )
    mode_group.add_argument(
        "--diff-file",
        metavar="PATH",
        help="Scan an explicit diff file, or '-' to read from standard input.",
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Terminal output format: 'text' (default) or 'json'.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save structured JSON report to specified file path.",
    )
    parser.add_argument(
        "--redacted-diff-out",
        metavar="FILE",
        help="Save sanitized diff patch with secrets masked to file.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Severity threshold causing exit code 1 (default: 'high').",
    )
    parser.add_argument(
        "--exclude",
        metavar="PATTERNS",
        help="Comma-separated file glob patterns to exclude from scanning (e.g. 'tests/*,examples/*').",
    )
    parser.add_argument(
        "--ai", "--ai-review",
        dest="ai",
        action="store_true",
        help="Run local AI review with Gemma model via Ollama following scan.",
    )
    parser.add_argument(
        "--ai-model",
        default="gemma3:4b",
        help="Local Ollama model identifier (default: 'gemma3:4b').",
    )
    parser.add_argument(
        "--ai-url",
        default="http://127.0.0.1:11434",
        help="Local Ollama endpoint URL (default: 'http://127.0.0.1:11434').",
    )
    parser.add_argument(
        "--require-ai",
        action="store_true",
        help="Fail scan with exit code 2 if local AI model / Ollama is unreachable.",
    )
    parser.add_argument(
        "--repo-root",
        metavar="PATH",
        default=".",
        help="Path to repository root (default: current directory).",
    )

    args = parser.parse_args(argv)

    root_path = Path(args.repo_root).resolve()
    license_status = check_root_license(root_path)

    exclude_patterns = [
        p.strip() for p in args.exclude.split(",") if p.strip()
    ] if args.exclude else []

    # Determine diff source mode
    if args.staged:
        mode = "staged"
    elif args.unstaged:
        mode = "unstaged"
    elif args.base:
        mode = "base"
    elif args.diff_file:
        mode = "file"
    else:
        mode = "all"

    diff_text = ""
    errors: List[str] = []

    if mode == "file":
        try:
            if args.diff_file == "-":
                diff_text = sys.stdin.read()
            else:
                diff_text = Path(args.diff_file).read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            errors.append(f"Failed to read diff file '{args.diff_file}': {exc}")
    else:
        diff_text, git_errors = get_git_diff(mode, base=args.base, cwd=root_path)
        errors.extend(git_errors)

    if errors:
        report = ScanReport(
            status="error",
            scan_mode=mode,
            license=license_status,
            errors=errors,
        )
        if args.output:
            try:
                Path(args.output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
            except Exception:
                pass
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print_text_report(report)
        return 2

    # Parse and scan
    added_lines = parse_unified_diff(diff_text)
    findings = scan_added_lines(added_lines, exclude_patterns=exclude_patterns)
    summary = calculate_summary(findings)

    report = ScanReport(
        status="completed",
        scan_mode=mode,
        findings=findings,
        license=license_status,
        summary=summary,
        errors=[],
    )

    # Run integrated local AI review if requested
    if args.ai:
        try:
            try:
                from ai_review import run_ai_review
            except ImportError:
                from scripts.ai_review import run_ai_review

            sanitized_patch = generate_sanitized_patch(diff_text)
            findings_dicts = [f.to_dict() for f in findings]
            report.ai_review = run_ai_review(
                findings=findings_dicts,
                sanitized_diff=sanitized_patch,
                model=args.ai_model,
                ollama_url=args.ai_url,
            )
        except Exception as exc:
            report.ai_review = {
                "status": "error",
                "model": args.ai_model,
                "error_type": "invocation_error",
                "message": f"Failed to invoke local AI reviewer: {exc}",
            }

        if args.require_ai and report.ai_review.get("status") == "error":
            report.errors.append(f"Required AI review failed: {report.ai_review.get('message')}")
            report.status = "error"

    # Save sanitized patch if requested
    if args.redacted_diff_out:
        try:
            sanitized_patch = generate_sanitized_patch(diff_text)
            Path(args.redacted_diff_out).write_text(sanitized_patch, encoding="utf-8")
        except Exception as exc:
            report.errors.append(f"Failed to write sanitized patch: {exc}")

    # Save JSON report if requested
    if args.output:
        try:
            Path(args.output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        except Exception as exc:
            report.errors.append(f"Failed to write JSON report to '{args.output}': {exc}")

    # Output to stdout
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_text_report(report)

    # Check for required AI failure
    if args.require_ai and report.ai_review and report.ai_review.get("status") == "error":
        return 2

    # Check failure threshold
    threshold = args.fail_on.lower()
    if threshold != "none":
        threshold_rank = SEVERITY_ORDER.get(threshold, 3)
        for f in findings:
            finding_rank = SEVERITY_ORDER.get(f.severity.lower(), 0)
            if finding_rank >= threshold_rank:
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
