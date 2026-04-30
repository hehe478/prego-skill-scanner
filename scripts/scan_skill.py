#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_MAX_FILE_KB = 512
SENSITIVE_SNIPPET = "[sensitive file detected; content suppressed]"
EXCLUDED_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".venv"}
ALLOWED_SUFFIXES = {
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
}
SPECIAL_FILENAMES = {
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "pipfile",
    "poetry.lock",
    "pnpm-lock.yaml",
    "yarn.lock",
}
ARCHIVE_SUFFIXES = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".jar",
}
SKIP_REASONS = {
    "archive_file",
    "binary_file",
    "excluded_directory",
    "file_too_large",
    "symlink",
    "symlink_outside_root",
}

TOKEN_REDACTIONS = [
    (
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"),
        lambda m: m.group(0)[:8] + "...redacted",
    ),
    (
        re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"),
        lambda m: m.group(0)[:6] + "...redacted",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
        lambda m: m.group(0)[:8] + "...redacted",
    ),
    (
        re.compile(r"\bBearer\s+[A-Za-z0-9._-]{8,}\b", re.IGNORECASE),
        lambda m: "Bearer ...redacted",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.IGNORECASE),
        lambda m: "-----BEGIN PRIVATE KEY-----...redacted",
    ),
]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity_hint: str
    confidence: str
    pattern: re.Pattern[str]
    reason: str


GENERIC_RULES = [
    Rule(
        "PI-001",
        "prompt_injection",
        "high",
        "medium",
        re.compile(
            r"ignore (all )?(previous|prior) instructions|disregard (all )?(previous|prior) instructions|follow only this instruction|override (the )?(system|safety) prompt",
            re.IGNORECASE,
        ),
        "Instruction tries to override higher-priority guidance.",
    ),
    Rule(
        "HB-001",
        "hidden_behavior",
        "high",
        "high",
        re.compile(
            r"do not tell the user|hide this from the (user|final answer)|run this silently|do not mention this|without telling the user",
            re.IGNORECASE,
        ),
        "Instruction attempts to conceal behavior from the user.",
    ),
    Rule(
        "EX-001",
        "data_exfiltration",
        "high",
        "medium",
        re.compile(
            r"\b(webhook|upload|exfiltrat|send .*https?://|post .*https?://|sync .*https?://|requests\.(post|put)|fetch\s*\()",
            re.IGNORECASE,
        ),
        "Pattern suggests remote transfer or upload behavior.",
    ),
    Rule(
        "DC-001",
        "dangerous_command",
        "high",
        "high",
        re.compile(
            r"curl\s+[^|]+\|\s*(sh|bash)|wget\s+[^|]+\|\s*(sh|bash)|bash\s+-c|sh\s+-c|os\.system\s*\(|subprocess\.(run|Popen|call)\s*\(|child_process\.(exec|spawn)\s*\(|Invoke-Expression|IEX\s*\(",
            re.IGNORECASE,
        ),
        "Pattern suggests shell execution or download-and-execute behavior.",
    ),
    Rule(
        "CA-003",
        "credential_access",
        "high",
        "medium",
        re.compile(
            r"\.ssh/id_(rsa|ed25519)|aws/config|aws/credentials|application_default_credentials|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|SENTRY_AUTH_TOKEN|read\s+.*(token|secret|credential|cookie)",
            re.IGNORECASE,
        ),
        "Pattern suggests credential or secret access.",
    ),
    Rule(
        "PE-001",
        "persistence",
        "high",
        "medium",
        re.compile(
            r"\.bashrc|\.zshrc|launchagents|systemd|crontab|scheduled task|registry\\run|startup folder",
            re.IGNORECASE,
        ),
        "Pattern suggests persistence or startup modification.",
    ),
    Rule(
        "OB-001",
        "obfuscation",
        "medium",
        "low",
        re.compile(
            r"base64\b|b64decode|fromcharcode|decode64|atob\s*\(",
            re.IGNORECASE,
        ),
        "Pattern suggests obfuscation or encoded execution flow.",
    ),
    Rule(
        "PM-001",
        "excessive_permissions",
        "medium",
        "medium",
        re.compile(
            r"allowed-tools:|bash\(\*\)|read\(\*\)|write\(\*\)|full disk access|ignore permission",
            re.IGNORECASE,
        ),
        "Pattern suggests broader permissions than a narrow skill needs.",
    ),
    Rule(
        "FS-001",
        "unsafe_file_writes",
        "high",
        "high",
        re.compile(
            r"rm\s+-rf\s+|>>\s*~/.+(bashrc|zshrc)|>\s*~/.+(bashrc|zshrc)|del\s+/f|copy-item .*profile|write.*~/.+",
            re.IGNORECASE,
        ),
        "Pattern suggests destructive or scope-breaking file writes.",
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lightweight static scanner for local skill poisoning and dangerous behavior."
    )
    parser.add_argument("target", help="Target skill directory or file")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--json-out", help="Write JSON report to a file")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting an existing --json-out file",
    )
    parser.add_argument(
        "--max-file-kb",
        type=int,
        default=DEFAULT_MAX_FILE_KB,
        help="Maximum file size to scan in KiB",
    )
    return parser.parse_args()


def redact_snippet(text: str) -> str:
    redacted = text.strip()
    for pattern, repl in TOKEN_REDACTIONS:
        redacted = pattern.sub(repl, redacted)
    return redacted


def is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    return False


def is_archive(path: Path) -> bool:
    suffixes = {suffix.lower() for suffix in path.suffixes}
    return bool(suffixes & ARCHIVE_SUFFIXES) or path.suffix.lower() in ARCHIVE_SUFFIXES


def normalized_name(path: Path) -> str:
    return path.name.lower()


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except Exception:
        try:
            return path.resolve(strict=False).relative_to(root).as_posix()
        except Exception:
            return path.name


def path_within_root(resolved: Path, root: Path) -> bool:
    try:
        resolved.relative_to(root)
        return True
    except ValueError:
        return False


def classify_sensitive_path(path: Path) -> tuple[bool, str | None, str | None]:
    rel = path.as_posix()
    name = normalized_name(path)

    if name in {".env.example", ".env.sample", ".env.template"}:
        return True, "CA-002", "example_env_file"

    exact_names = {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "id_rsa",
        "id_ed25519",
        "known_hosts",
        "authorized_keys",
        "credentials.json",
        "secrets.json",
    }
    if name in exact_names:
        return True, "CA-001", "sensitive_file"

    if name.startswith(".env."):
        return True, "CA-001", "sensitive_file"

    if name.endswith(".pem") or name.endswith(".key") or name.endswith(".p12") or name.endswith(".pfx"):
        return True, "CA-001", "sensitive_file"

    if "service-account" in name and name.endswith(".json"):
        return True, "CA-001", "sensitive_file"

    suffix_match = {
        ".aws/credentials",
        ".aws/config",
        ".config/gcloud/application_default_credentials.json",
        ".docker/config.json",
        ".kube/config",
    }
    if any(rel.endswith(item) for item in suffix_match):
        return True, "CA-001", "sensitive_file"

    return False, None, None


def should_scan_in_directory_mode(path: Path) -> bool:
    if path.suffix.lower() in ALLOWED_SUFFIXES:
        return True
    return normalized_name(path) in SPECIAL_FILENAMES


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def add_finding(
    findings: list[dict],
    *,
    rule_id: str,
    category: str,
    severity_hint: str,
    confidence: str,
    path: str,
    line: int | None,
    snippet: str,
    reason: str,
) -> None:
    findings.append(
        {
            "rule_id": rule_id,
            "category": category,
            "severity_hint": severity_hint,
            "confidence": confidence,
            "path": path,
            "line": line,
            "snippet": snippet,
            "reason": reason,
        }
    )


def scan_text_file(path: Path, rel_path: str, text: str, findings: list[dict]) -> None:
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for rule in GENERIC_RULES:
            if rule.pattern.search(line):
                add_finding(
                    findings,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity_hint=rule.severity_hint,
                    confidence=rule.confidence,
                    path=rel_path,
                    line=line_no,
                    snippet=redact_snippet(line),
                    reason=rule.reason,
                )


def scan_package_json(path: Path, rel_path: str, text: str, findings: list[dict]) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return

    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return

    lifecycle_names = ["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"]
    found = [name for name in lifecycle_names if name in scripts]
    if not found:
        return

    snippet = ", ".join(found)
    line_no = None
    line_map = text.splitlines()
    for idx, line in enumerate(line_map, start=1):
        if any(f'"{name}"' in line for name in found):
            line_no = idx
            break

    add_finding(
        findings,
        rule_id="LS-001",
        category="dependency_lifecycle",
        severity_hint="high",
        confidence="high",
        path=rel_path,
        line=line_no,
        snippet=redact_snippet(snippet),
        reason="package.json defines install-time lifecycle scripts.",
    )


def scan_setup_py(rel_path: str, text: str, findings: list[dict]) -> None:
    patterns = [
        re.compile(r"class\s+\w+\s*\([^)]*install[^)]*\)", re.IGNORECASE),
        re.compile(r"cmdclass\s*=.*install", re.IGNORECASE),
    ]
    for pattern in patterns:
        match = pattern.search(text)
        if not match:
            continue
        line_no = text[: match.start()].count("\n") + 1
        line = text.splitlines()[line_no - 1]
        add_finding(
            findings,
            rule_id="LS-002",
            category="dependency_lifecycle",
            severity_hint="medium",
            confidence="medium",
            path=rel_path,
            line=line_no,
            snippet=redact_snippet(line),
            reason="setup.py appears to define custom install-time behavior.",
        )
        break


def summarize(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"Target: {report['root']}",
        f"Mode: {report['mode']}",
        f"Files scanned: {summary['files_scanned']}",
        f"Files skipped: {summary['files_skipped']}",
        f"Findings: {summary['findings']}",
    ]
    if report["findings"]:
        lines.append("Top findings:")
        for finding in report["findings"][:8]:
            location = finding["path"]
            if finding["line"]:
                location = f"{location}:{finding['line']}"
            lines.append(
                f"- {finding['rule_id']} {finding['severity_hint']} {location} :: {finding['reason']}"
            )
    if report["skipped"]:
        lines.append("Skipped items:")
        for item in report["skipped"][:8]:
            lines.append(f"- {item['path']} :: {item['reason']}")
    return "\n".join(lines)


def stable_sort(items: Iterable[dict]) -> list[dict]:
    return sorted(
        items,
        key=lambda item: (
            item.get("path", ""),
            -1 if item.get("line") is None else item.get("line", -1),
            item.get("rule_id", ""),
            item.get("reason", ""),
        ),
    )


def make_skip(path: str, reason: str, **extra: object) -> dict:
    item = {"path": path, "reason": reason}
    item.update(extra)
    return item


def handle_sensitive_file(rel_path: str, rule_id: str, sensitive_kind: str, findings: list[dict]) -> None:
    if sensitive_kind == "example_env_file":
        add_finding(
            findings,
            rule_id=rule_id,
            category="credential_access",
            severity_hint="low",
            confidence="low",
            path=rel_path,
            line=None,
            snippet=SENSITIVE_SNIPPET,
            reason=".env example/template file detected; suspicious by presence only.",
        )
    else:
        add_finding(
            findings,
            rule_id=rule_id,
            category="credential_access",
            severity_hint="medium",
            confidence="medium",
            path=rel_path,
            line=None,
            snippet=SENSITIVE_SNIPPET,
            reason="Sensitive file detected; content intentionally not read.",
        )


def process_file(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    directory_mode: bool,
    findings: list[dict],
    skipped: list[dict],
) -> bool:
    rel_path = relative_path(path, root)

    if path.is_symlink():
        resolved = path.resolve(strict=False)
        reason = "symlink_outside_root" if not path_within_root(resolved, root) else "symlink"
        skipped.append(make_skip(rel_path, reason))
        return False

    if is_archive(path):
        skipped.append(make_skip(rel_path, "archive_file"))
        return False

    sensitive, rule_id, sensitive_kind = classify_sensitive_path(Path(rel_path))
    if sensitive and rule_id and sensitive_kind:
        handle_sensitive_file(rel_path, rule_id, sensitive_kind, findings)
        return True

    try:
        size_bytes = path.stat().st_size
    except OSError:
        skipped.append(make_skip(rel_path, "binary_file"))
        return False

    if size_bytes > max_bytes:
        skipped.append(
            make_skip(
                rel_path,
                "file_too_large",
                size_bytes=size_bytes,
                limit_bytes=max_bytes,
            )
        )
        return False

    if is_binary_file(path):
        skipped.append(make_skip(rel_path, "binary_file"))
        return False

    if directory_mode and not should_scan_in_directory_mode(path):
        return False

    text = load_text(path)
    scan_text_file(path, rel_path, text, findings)

    if normalized_name(path) == "package.json":
        scan_package_json(path, rel_path, text, findings)
    elif normalized_name(path) == "setup.py":
        scan_setup_py(rel_path, text, findings)

    return True


def scan_target(target: Path, max_bytes: int) -> dict:
    if not target.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    findings: list[dict] = []
    skipped: list[dict] = []
    files_scanned = 0

    if target.is_dir():
        root = target.resolve()
        for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current_root)

            kept_dirs = []
            for dirname in dirnames:
                dir_path = current_path / dirname
                rel_dir = relative_path(dir_path, root)
                if dir_path.is_symlink():
                    resolved = dir_path.resolve(strict=False)
                    reason = "symlink_outside_root" if not path_within_root(resolved, root) else "symlink"
                    skipped.append(make_skip(rel_dir, reason))
                    continue
                if dirname in EXCLUDED_DIRS:
                    skipped.append(make_skip(rel_dir, "excluded_directory"))
                    continue
                kept_dirs.append(dirname)
            dirnames[:] = kept_dirs

            for filename in filenames:
                file_path = current_path / filename
                if process_file(
                    file_path,
                    root=root,
                    max_bytes=max_bytes,
                    directory_mode=True,
                    findings=findings,
                    skipped=skipped,
                ):
                    files_scanned += 1

        mode = "directory"
    else:
        root = target.parent.resolve()
        if process_file(
            target,
            root=root,
            max_bytes=max_bytes,
            directory_mode=False,
            findings=findings,
            skipped=skipped,
        ):
            files_scanned += 1
        mode = "single_file"

    findings = stable_sort(findings)
    skipped = stable_sort(skipped)
    return {
        "root": str(root),
        "mode": mode,
        "summary": {
            "files_scanned": files_scanned,
            "files_skipped": len(skipped),
            "findings": len(findings),
        },
        "findings": findings,
        "skipped": skipped,
    }


def write_json_out(report: dict, output_path: Path, overwrite: bool) -> None:
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {output_path}")
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    max_bytes = args.max_file_kb * 1024
    target = Path(args.target)

    try:
        report = scan_target(target, max_bytes)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json:
        print(report_json)
    else:
        print(summarize(report))

    if args.json_out:
        try:
            write_json_out(report, Path(args.json_out), args.overwrite)
        except Exception as exc:
            print(f"Failed to write JSON output: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
