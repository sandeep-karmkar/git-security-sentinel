#!/usr/bin/env python3
"""Git Security Sentinel - Local AI Security Reviewer.

Connects strictly to a local, loopback Ollama endpoint (default: http://127.0.0.1:11434)
to provide contextual security analysis, false-positive assessment, and safer code
alternatives for findings produced by scan_diff.py.

Privacy Guarantees:
- Zero cloud or third-party network calls. Rejects non-loopback addresses by default.
- Scrutinizes only sanitized, redacted reports and diffs; secrets are never passed to the LLM.
- Model advice is treated as untrusted: AI cannot alter deterministic findings or exit codes.
- Standard library only: no external dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "gemma3:4b"
DEFAULT_TIMEOUT_SECONDS = 45


def is_loopback_host(url: str) -> bool:
    """Validate that the target URL resolves to local loopback interface."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()
        return hostname in {"127.0.0.1", "localhost", "::1"}
    except Exception:
        return False


def build_system_prompt() -> str:
    return (
        "You are Git Security Sentinel's local AI security reviewer. "
        "Your task is to analyze static security scan findings from a Git diff. "
        "For each finding, provide:\n"
        "1. Risk Analysis: Explain why this pattern is dangerous in production.\n"
        "2. False Positive Assessment: Determine whether this is likely a genuine risk, test fixture, or benign code.\n"
        "3. Prioritization: Rank urgency (Immediate Action, High Priority, Low Priority, or Benign/Ignore).\n"
        "4. Safe Alternative: Concrete, safe code example or remediation technique.\n\n"
        "IMPORTANT RULES:\n"
        "- All evidence strings are already redacted. Do not guess or attempt to reconstruct secrets.\n"
        "- Do not execute commands or provide instructions to circumvent security policies.\n"
        "- Provide clear, concise, developer-friendly recommendations.\n"
        "- Respond in valid JSON format matching the requested schema."
    )


def build_user_prompt(findings: List[Dict[str, Any]], sanitized_diff: Optional[str] = None) -> str:
    prompt_data: Dict[str, Any] = {
        "findings_count": len(findings),
        "findings": findings,
    }
    if sanitized_diff:
        # Include a truncated excerpt of sanitized diff if available
        prompt_data["sanitized_diff_excerpt"] = sanitized_diff[:3000]

    return (
        "Review the following sanitized Git security scan findings and return a JSON object with this exact structure:\n"
        "{\n"
        '  "summary": "Executive summary of changes and risks",\n'
        '  "reviews": [\n'
        "    {\n"
        '      "rule_id": "rule identifier",\n'
        '      "file": "path",\n'
        '      "line": 0,\n'
        '      "assessment": "genuine_risk | likely_false_positive | context_dependent",\n'
        '      "risk_explanation": "detailed risk context",\n'
        '      "safe_alternative": "remediation advice or code snippet"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        f"Input Data:\n{json.dumps(prompt_data, indent=2)}"
    )


def call_ollama(
    endpoint: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Send an HTTP request to local Ollama /api/generate endpoint."""
    api_url = f"{endpoint.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "system": system_prompt,
        "prompt": user_prompt,
        "stream": False,
        "format": "json",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)
            raw_response = res_json.get("response", "{}")
            # Parse the model's inner JSON text
            try:
                parsed_model_data = json.loads(raw_response)
                return {
                    "status": "success",
                    "model": model,
                    "review": parsed_model_data,
                }
            except json.JSONDecodeError:
                return {
                    "status": "partial_success",
                    "model": model,
                    "raw_response": raw_response,
                }
    except urllib.error.URLError as err:
        reason = getattr(err, "reason", str(err))
        return {
            "status": "error",
            "model": model,
            "error_type": "connection_error",
            "message": f"Unable to reach local Ollama at {endpoint}: {reason}. Ensure Ollama is running (`ollama serve`).",
        }
    except TimeoutError:
        return {
            "status": "error",
            "model": model,
            "error_type": "timeout",
            "message": f"Ollama model inference timed out after {timeout} seconds.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "model": model,
            "error_type": "unexpected_error",
            "message": f"Unexpected error during local AI review: {exc}",
        }


def run_ai_review(
    findings: List[Dict[str, Any]],
    sanitized_diff: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    ollama_url: str = DEFAULT_OLLAMA_HOST,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    allow_remote_host: bool = False,
) -> Dict[str, Any]:
    """Execute local Ollama AI review on findings, returning structured results."""
    if not allow_remote_host and not is_loopback_host(ollama_url):
        return {
            "status": "error",
            "model": model,
            "error_type": "security_refusal",
            "message": f"'{ollama_url}' is not a local loopback address (127.0.0.1 / localhost).",
        }

    if not findings:
        return {
            "status": "skipped",
            "model": model,
            "message": "No findings to review.",
        }

    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(findings, sanitized_diff)

    return call_ollama(
        endpoint=ollama_url,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        timeout=timeout,
    )


def print_ai_review(result: Dict[str, Any], out_stream=sys.stdout) -> None:
    """Print readable terminal output for AI review."""
    print("=" * 70, file=out_stream)
    print("  GIT SECURITY SENTINEL - LOCAL AI REVIEW (GEMMA)", file=out_stream)
    print("=" * 70, file=out_stream)
    print(f"Status      : {result.get('status', 'unknown').upper()}", file=out_stream)
    print(f"Model       : {result.get('model', 'unknown')}", file=out_stream)

    if result.get("status") == "error":
        print(f"\n[!] AI Review Unavailable: {result.get('message')}", file=out_stream)
        print("    Note: The static scanner findings remain valid and unaffected.", file=out_stream)
        print("=" * 70, file=out_stream)
        return

    review = result.get("review")
    if isinstance(review, dict):
        summary = review.get("summary", "No summary provided.")
        print(f"\nAI Summary  :\n  {summary}\n", file=out_stream)
        reviews = review.get("reviews", [])
        if reviews:
            print("[*] Detailed Findings Analysis:\n", file=out_stream)
            for idx, r in enumerate(reviews, start=1):
                rule = r.get("rule_id", "Unknown")
                loc = f"{r.get('file', 'unknown')}:{r.get('line', '?')}"
                assessment = r.get("assessment", "unspecified").replace("_", " ").upper()
                print(f"  {idx}. [{assessment}] {rule} at {loc}", file=out_stream)
                print(f"     Context : {r.get('risk_explanation', 'N/A')}", file=out_stream)
                print(f"     Remedy  : {r.get('safe_alternative', 'N/A')}", file=out_stream)
                print("", file=out_stream)
    elif "raw_response" in result:
        print("\nModel Output (Raw):\n", file=out_stream)
        print(result["raw_response"], file=out_stream)

    print("=" * 70, file=out_stream)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai_review.py",
        description="Local AI reviewer for Git Security Sentinel using Ollama (Python standard library only).",
    )
    parser.add_argument(
        "--report",
        required=True,
        metavar="JSON_FILE",
        help="Path to JSON scan report generated by scan_diff.py.",
    )
    parser.add_argument(
        "--diff",
        metavar="DIFF_FILE",
        help="Optional path to sanitized diff patch file.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model identifier (default: '{DEFAULT_MODEL}').",
    )
    parser.add_argument(
        "--ollama-url",
        default=DEFAULT_OLLAMA_HOST,
        help=f"Ollama server URL (default: '{DEFAULT_OLLAMA_HOST}').",
    )
    parser.add_argument(
        "--allow-remote-host",
        action="store_true",
        help="Explicitly permit non-loopback Ollama URLs (disabled by default for privacy).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save AI review output to specified JSON file.",
    )

    args = parser.parse_args(argv)

    # Privacy check: Ensure loopback endpoint unless explicitly permitted
    if not args.allow_remote_host and not is_loopback_host(args.ollama_url):
        print(
            f"[!] Security Refusal: '{args.ollama_url}' is not a local loopback address (127.0.0.1 / localhost).\n"
            "    To preserve confidentiality, Git Security Sentinel rejects remote endpoints.\n"
            "    Use --allow-remote-host if this is an intentional private server.",
            file=sys.stderr,
        )
        return 2

    # Load scanner report
    try:
        report_data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[!] Error loading scan report '{args.report}': {exc}", file=sys.stderr)
        return 2

    findings = report_data.get("findings", [])
    if not findings:
        print("[+] No findings in report to review. Code is clean.")
        return 0

    # Load optional sanitized diff
    sanitized_diff: Optional[str] = None
    if args.diff:
        try:
            sanitized_diff = Path(args.diff).read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            print(f"[!] Warning: Could not read diff file '{args.diff}': {exc}", file=sys.stderr)

    # Construct prompts
    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(findings, sanitized_diff)

    # Call local Ollama
    result = call_ollama(
        endpoint=args.ollama_url,
        model=args.model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        timeout=args.timeout,
    )

    print_ai_review(result)

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"[!] Failed to write review output to '{args.output}': {exc}", file=sys.stderr)

    # Note: AI review failures return code 0 or 2 for invocation issues, but do not override scanner exit code
    return 0 if result.get("status") in {"success", "partial_success"} else 1


if __name__ == "__main__":
    sys.exit(main())
