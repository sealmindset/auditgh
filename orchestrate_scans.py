#!/usr/bin/env python3
"""
Multi-scanner orchestrator for AuditGH.

Runs the existing scan_* scripts in a controlled sequence with sensible defaults
and profiles (fast, balanced, deep). Produces a high-level orchestration summary
with durations, statuses, and links to per-tool reports.

This orchestrator does NOT reimplement scanning logic; it delegates to the
existing scripts in this repository.
"""
import argparse
import datetime
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    def load_dotenv(*args, **kwargs):  # type: ignore
        return False

# Load environment variables from .env if present
load_dotenv(override=True)

REPO_ROOT = Path(__file__).resolve().parent
# If REPORT_DIR is provided (e.g., by the server orchestrator), write outputs into that mounted path
REPORT_DIR_ENV = os.getenv("REPORT_DIR")
BASE_OUT_DIR = Path(REPORT_DIR_ENV) if REPORT_DIR_ENV else REPO_ROOT
LOGS_DIR = BASE_OUT_DIR / "logs"
SUMMARY_DIR = BASE_OUT_DIR / "markdown"
SUMMARY_FILE = SUMMARY_DIR / "orchestration_summary.md"

# Known scanners and default output locations (for linking in the summary)
SCANNER_REPORT_LINKS: Dict[str, List[Path]] = {
    "cicd": [REPO_ROOT / "ci_reports" / "ci_summary.md"],
    "gitleaks": [REPO_ROOT / "secrets_reports" / "secrets_scan_summary.md"],
    "trufflehog": [REPO_ROOT / "secrets_reports" / "trufflehog_summary.md"],
    "hardcoded_ips": [REPO_ROOT / "hardcoded_ips_reports" / "HARDCODED_IPS_SUMMARY.md"],
    "oss": [REPO_ROOT / "oss_reports" / "oss_summary.md"],
    "terraform": [REPO_ROOT / "terraform_reports" / "terraform_scan_summary.md"],
    "codeql": [REPO_ROOT / "codeql_reports" / "codeql_summary.md"],
    # contributors has per-repo reports only; link to directory
    "contributors": [REPO_ROOT / "contributors_reports"],
    # binaries scanner summary
    "binaries": [REPO_ROOT / "binaries_reports" / "binaries_scan_summary.md"],
    "linecount": [REPO_ROOT / "linecount_reports" / "linecount_scan_summary.md"],
    # genai tokens scanner
    "genai_tokens": [REPO_ROOT / "genai_tokens_reports"],
    # engagement snapshots are persisted to PostgREST; no local report
    "engagement": [],
    # shai_hulud scan currently logs only; no markdown summary
    "shai_hulud": [],
}

# Profile-based defaults for CodeQL query suite and timeout
PROFILE_TO_SUITE = {
    "fast": "code-scanning",
    "balanced": "security-extended",
    "deep": "security-and-quality",
}
PROFILE_TO_TIMEOUT = {
    "fast": 1200,
    "balanced": 1800,
    "deep": 3600,
}

@dataclass
class RunResult:
    name: str
    command: List[str]
    start: datetime.datetime
    end: datetime.datetime
    returncode: int
    log_file: Path

    @property
    def duration(self) -> str:
        delta = self.end - self.start
        return str(delta)


def _verbosity_flags(level: int) -> List[str]:
    if level <= 0:
        return ["-q"]
    # Repeat -v level times (many scripts support -v as count)
    return ["-v" for _ in range(level)]


def _build_scanner_commands(args: argparse.Namespace) -> List[Dict[str, object]]:
    org = args.org or os.getenv("GITHUB_ORG")
    token = args.token or os.getenv("GITHUB_TOKEN")
    repo = getattr(args, 'repo', None)

    if not org:
        raise SystemExit("GITHUB_ORG is required (set in .env or pass --org)")
    if not token:
        # Several scripts rely on env; passing --token improves consistency
        # but we still allow env-only usage. Warn in logs via summary header.
        pass

    include_flags = []
    if args.include_forks:
        include_flags += ["--include-forks"]
    if args.include_archived:
        include_flags += ["--include-archived"]

    vflags = _verbosity_flags(args.verbose)

    # Detect optional tools for OSS flags
    has_syft = shutil.which("syft") is not None
    has_grype = shutil.which("grype") is not None

    scanners: List[str] = [
        "cicd",
        "gitleaks",
        "trufflehog",
        "hardcoded_ips",
        "oss",
        "terraform",
        "codeql",
        "contributors",
        "binaries",
        "linecount",
        "engagement",
        "shai_hulud",
        "genai_tokens",
    ]

    if args.only:
        only = {s.strip().lower() for s in args.only.split(",") if s.strip()}
        scanners = [s for s in scanners if s in only]
    if args.skip:
        skip = {s.strip().lower() for s in args.skip.split(",") if s.strip()}
        scanners = [s for s in scanners if s not in skip]

    cmds: List[Dict[str, object]] = []

    # cicd
    if "cicd" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_cicd.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "cicd", "cmd": cmd})

    # gitleaks
    if "gitleaks" in scanners:
        # Writes secrets_reports/* and a summary
        cmd = [sys.executable, str(REPO_ROOT / "scan_gitleaks.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        postgrest_url = os.getenv("POSTGREST_URL") or "http://localhost:3001"
        cmd += ["--persist", "--postgrest-url", postgrest_url]
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "gitleaks", "cmd": cmd})

    # trufflehog
    if "trufflehog" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_trufflehog.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        postgrest_url = os.getenv("POSTGREST_URL") or "http://localhost:3001"
        cmd += ["--persist", "--postgrest-url", postgrest_url]
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "trufflehog", "cmd": cmd})

    # hardcoded_ips (Semgrep)
    if "hardcoded_ips" in scanners:
        hc_flags = ["--parallel", "4"] if args.profile == "balanced" else (["--parallel", "1"] if args.profile == "fast" else ["--parallel", "8"])
        # Append ignore filters if specified on orchestrator
        if getattr(args, "ignore_private", False):
            hc_flags += ["--ignore-private"]
        if getattr(args, "ignore_localhost", False):
            hc_flags += ["--ignore-localhost"]
        if getattr(args, "ignore_example", False):
            hc_flags += ["--ignore-example"]
        cmd = [sys.executable, str(REPO_ROOT / "scan_hardcoded_ips.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += hc_flags + vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "hardcoded_ips", "cmd": cmd})

    # oss
    if "oss" in scanners:
        oss_flags = ["--tools", "pip-audit", "safety", "osv-scanner", "--parse-osv-cvss"]
        if has_syft:
            oss_flags += ["--enable-syft", "--syft-format", "cyclonedx-json"]
        if has_grype:
            oss_flags += ["--enable-grype", "--grype-scan-mode", "sbom"]
        cmd = [sys.executable, str(REPO_ROOT / "scan_oss.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += oss_flags + vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "oss", "cmd": cmd})

    # terraform
    if "terraform" in scanners:
        tf_flags = ["--refresh-kev", "--refresh-epss"]
        if args.profile == "deep" and not args.no_deep_terraform:
            tf_flags += ["--with-trivy-fs"]
        cmd = [sys.executable, str(REPO_ROOT / "scan_terraform.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += tf_flags + vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "terraform", "cmd": cmd})

    # codeql
    if "codeql" in scanners:
        # Determine suite and timeout with precedence: CLI > env > profile defaults
        suite_override = getattr(args, "codeql_query_suite", None) or os.getenv("ORCHESTRATOR_CODEQL_QUERY_SUITE")
        suite = suite_override or PROFILE_TO_SUITE.get(args.profile, "code-scanning")
        timeout_arg = getattr(args, "codeql_timeout_seconds", None)
        env_timeout_raw = os.getenv("ORCHESTRATOR_CODEQL_TIMEOUT")
        timeout_env: Optional[int] = None
        try:
            timeout_env = int(env_timeout_raw) if env_timeout_raw else None
        except Exception:
            timeout_env = None
        timeout_seconds = (
            timeout_arg if (isinstance(timeout_arg, int) and timeout_arg > 0)
            else (timeout_env if (isinstance(timeout_env, int) and timeout_env > 0)
                  else PROFILE_TO_TIMEOUT.get(args.profile, 1800))
        )
        # Optional language targeting (CLI > env). Comma-separated list becomes multiple --languages args
        langs_csv = getattr(args, "codeql_languages", None) or os.getenv("ORCHESTRATOR_CODEQL_LANGUAGES")
        langs: Optional[List[str]] = None
        if isinstance(langs_csv, str) and langs_csv.strip():
            langs = [s.strip() for s in langs_csv.split(",") if s.strip()]
        # Optional skip autobuild for compiled languages (CLI OR env truthy)
        skip_env_raw = os.getenv("ORCHESTRATOR_CODEQL_SKIP_AUTOBUILD", "")
        skip_env = skip_env_raw.lower() in ("1", "true", "yes", "on")
        skip_autobuild = bool(getattr(args, "codeql_skip_autobuild", False)) or skip_env
        cq_flags = [
            "--query-suite",
            suite,
            "--max-workers",
            str(args.max_workers),
            "--top-n",
            "200",
            "--timeout-seconds",
            str(timeout_seconds),
        ]
        if args.profile == "deep" and not args.no_deep_codeql:
            cq_flags += ["--recreate-db"]
        # Optional recreate DB toggle (CLI)
        if getattr(args, "codeql_recreate_db", False) and "--recreate-db" not in cq_flags:
            cq_flags += ["--recreate-db"]
        cmd = [sys.executable, str(REPO_ROOT / "scan_codeql.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += cq_flags
        if langs:
            cmd += ["--languages", *langs]
        if skip_autobuild:
            cmd += ["--skip-autobuild"]
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "codeql", "cmd": cmd})

    # contributors
    if "contributors" in scanners:
        contrib_flags = ["--exclude-bots"]
        if args.profile != "fast":
            # Balanced/deep: attribute secrets when present
            contrib_flags += ["--crosslink-findings", "--findings-dir", str(REPO_ROOT / "secrets_reports")]
        if args.profile == "deep" and not args.no_deep_contributors:
            contrib_flags += ["--compute-churn", "--with-pr-metrics"]
        cmd = [sys.executable, str(REPO_ROOT / "scan_contributor.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += contrib_flags + vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "contributors", "cmd": cmd})

    # binaries
    if "binaries" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_binaries.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "binaries", "cmd": cmd})

    # linecount
    if "linecount" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_linecount.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "linecount", "cmd": cmd})

    # genai_tokens (GenAI API token detection with persistence to PostgREST)
    if "genai_tokens" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_genai_tokens.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        # Persist by default and point to PostgREST
        postgrest_url = os.getenv("POSTGREST_URL") or "http://localhost:3001"
        cmd += ["--persist", "--postgrest-url", postgrest_url]
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "genai_tokens", "cmd": cmd})

    # engagement (stars/forks/watchers/issues to PostgREST if enabled)
    if "engagement" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_engagement.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += vflags
        if token:
            cmd += ["--token", token]
        # Optional persistence controlled by env
        postgrest_url = os.getenv("POSTGREST_URL") or "http://localhost:3001"
        persist_flag = os.getenv("PERSIST_ENGAGEMENT")
        if persist_flag and persist_flag.lower() not in ("0", "false", "no"):  # minimal toggle
            cmd += ["--persist", "--postgrest-url", postgrest_url]
        cmds.append({"name": "engagement", "cmd": cmd})

    # shai_hulud (Shai Hulud indicators scan)
    if "shai_hulud" in scanners:
        cmd = [sys.executable, str(REPO_ROOT / "scan_shai_hulud.py")]
        if repo:
            cmd += ["--repo", repo]
        else:
            cmd += ["--org", org] + include_flags
        cmd += vflags
        if token:
            cmd += ["--token", token]
        cmds.append({"name": "shai_hulud", "cmd": cmd})

    return cmds


def _write_summary(header: str, results: List[RunResult]) -> None:
    # Ensure we have a directory to write into; if 'markdown' exists as a file, fall back to repo root
    target_dir = SUMMARY_DIR
    if target_dir.exists() and not target_dir.is_dir():
        target_dir = REPO_ROOT
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append("# Orchestration Summary\n")
    lines.append(f"Generated: {datetime.datetime.now().isoformat()}\n\n")
    lines.append(header + "\n\n")
    lines.append("## Results\n\n")
    lines.append("| Scanner | Status | Exit Code | Duration | Log | Key Reports |\n")
    lines.append("|---------|--------|-----------:|---------:|-----|------------|\n")

    for r in results:
        status = "success" if r.returncode == 0 else ("findings" if r.returncode == 1 else "error")
        # Link known report summaries if present
        report_cells: List[str] = []
        for p in SCANNER_REPORT_LINKS.get(r.name, []):
            if p.exists():
                rel = os.path.relpath(p, target_dir)
                report_cells.append(f"[{p.name}]({rel})")
        reports_cell = ", ".join(report_cells)
        log_rel = os.path.relpath(r.log_file, target_dir) if r.log_file.exists() else str(r.log_file)
        lines.append(
            f"| {r.name} | {status} | {r.returncode} | {r.duration} | [{r.log_file.name}]({log_rel}) | {reports_cell} |\n"
        )

    # Append aggregated snippets for certain scanners if their summaries exist
    try:
        # Linecount aggregation: include total LOC and link
        lc_md = REPO_ROOT / "linecount_reports" / "linecount_scan_summary.md"
        if lc_md.exists():
            try:
                lc_text = lc_md.read_text(encoding="utf-8", errors="ignore").splitlines()
                total_line = next((ln for ln in lc_text if ln.strip().startswith("**Total LOC across repositories:**")), None)
                lines.append("\n## Linecount Summary\n\n")
                if total_line:
                    lines.append(f"{total_line}\n\n")
                # Link to full summary
                lc_rel = os.path.relpath(lc_md, target_dir)
                lines.append(f"See full details: [linecount_scan_summary.md]({lc_rel})\n\n")
            except Exception:
                pass
    except Exception:
        pass

    # Determine summary file path based on resolved target_dir
    summary_file = (target_dir / "orchestration_summary.md")
    with summary_file.open("w", encoding="utf-8") as f:
        f.write("".join(lines))


def _write_tool_versions() -> None:
    """Capture installed tool versions to logs/versions.log (best effort)."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    tools = [
        ["python", "--version"],
        ["pip", "--version"],
        ["git", "--version"],
        ["node", "-v"],
        ["npm", "-v"],
        ["ruby", "-v"],
        ["bundler-audit", "version"],
        ["go", "version"],
        ["govulncheck", "-version"],
        ["java", "-version"],
        ["semgrep", "--version"],
        ["gitleaks", "version"],
        ["trivy", "--version"],
        ["syft", "version"],
        ["grype", "version"],
        ["osv-scanner", "--version"],
        ["codeql", "--version"],
    ]
    for cmd in tools:
        try:
            proc = subprocess.run(cmd, cwd=str(REPO_ROOT), text=True, capture_output=True, check=False)
            header = f"$ {' '.join(cmd)}\n"
            body = proc.stdout or proc.stderr or "(no output)\n"
            out.append(header + body + ("\n" if not body.endswith("\n") else ""))
        except Exception as e:
            out.append(f"$ {' '.join(cmd)}\n(error: {e})\n\n")
    (LOGS_DIR / "versions.log").write_text("".join(out), encoding="utf-8")

def run_orchestrator(args: argparse.Namespace) -> int:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    # Write versions once per run (best effort)
    try:
        _write_tool_versions()
    except Exception:
        pass

    cmds = _build_scanner_commands(args)

    if args.dry_run:
        print("Planned commands (dry-run):\n")
        for it in cmds:
            print("$", " ".join(it["cmd"]))
        return 0

    results: List[RunResult] = []

    # Run scanners in small parallel windows to limit resource spikes
    parallel = max(1, int(args.scanners_parallel))

    # Chunk into windows of size `parallel`
    for i in range(0, len(cmds), parallel):
        window = cmds[i : i + parallel]
        with ThreadPoolExecutor(max_workers=parallel) as pool:
            fut_to_name: Dict[object, str] = {}
            fut_to_log: Dict[object, Path] = {}
            fut_to_cmd: Dict[object, List[str]] = {}
            fut_to_start: Dict[object, datetime.datetime] = {}
            for item in window:
                name = str(item["name"])
                cmd = list(item["cmd"])  # type: ignore
                log_path = LOGS_DIR / f"{name}.log"
                start = datetime.datetime.now()

                def _run(command: List[str], log_file: Path):
                    # Stream child output live to both the UI (stdout) and the log file
                    with log_file.open("w", encoding="utf-8") as lf:
                        lf.write(f"# Command\n{' '.join(command)}\n\n")
                        lf.write("# OUTPUT (stdout+stderr combined)\n\n")
                        lf.flush()
                        # Use Popen to stream combined output
                        proc = subprocess.Popen(
                            command,
                            cwd=str(REPO_ROOT),
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            bufsize=1,
                            universal_newlines=True,
                        )
                        try:
                            assert proc.stdout is not None
                            for line in proc.stdout:
                                # Write to file
                                lf.write(line)
                                # Echo to container stdout so server SSE picks it up
                                print(line, end="")
                            proc.wait()
                        finally:
                            try:
                                proc.stdout and proc.stdout.close()
                            except Exception:
                                pass
                        return int(proc.returncode or 0)

                fut = pool.submit(_run, cmd, log_path)
                fut_to_name[fut] = name
                fut_to_log[fut] = log_path
                fut_to_cmd[fut] = cmd
                fut_to_start[fut] = start

            for fut in as_completed(fut_to_name):
                name = fut_to_name[fut]
                log_file = fut_to_log[fut]
                cmd = fut_to_cmd[fut]
                start = fut_to_start[fut]
                rc = int(fut.result())
                end = datetime.datetime.now()
                results.append(RunResult(name=name, command=cmd, start=start, end=end, returncode=rc, log_file=log_file))
                if args.fail_fast and rc not in (0, 1):
                    break

    # Build header with env diagnostics (without printing secrets)
    org = args.org or os.getenv("GITHUB_ORG") or "(unset)"
    has_token = bool(args.token or os.getenv("GITHUB_TOKEN"))
    header = (
        f"Profile: {args.profile}\n"
        f"Parallel scanners: {args.scanners_parallel}\n"
        f"Organization: {org}\n"
        f"Token detected: {'yes' if has_token else 'no'}\n"
    )

    _write_summary(header, results)

    # Exit non-zero if any scanner returned a hard error
    hard_error = any(r.returncode not in (0, 1) for r in results)
    return 2 if hard_error else 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Orchestrate multiple AuditGH scanners")
    parser.add_argument("--org", type=str, help="GitHub org/user (overrides GITHUB_ORG)")
    parser.add_argument("--repo", type=str, help="Limit run to a single repository (owner/name or name)" )
    parser.add_argument("--token", type=str, help="GitHub token (overrides GITHUB_TOKEN)")

    parser.add_argument("--profile", choices=["fast", "balanced", "deep"], default="balanced")
    parser.add_argument("--only", type=str, help="Comma-separated subset of scanners to run (e.g., codeql,oss)")
    parser.add_argument("--skip", type=str, help="Comma-separated scanners to skip")

    parser.add_argument("--include-forks", action="store_true", help="Include forked repositories")
    parser.add_argument("--include-archived", action="store_true", help="Include archived repositories")

    parser.add_argument("--max-workers", type=int, default=6, help="Max workers for CodeQL repo-level concurrency")
    parser.add_argument("--codeql-query-suite", type=str, help="Override CodeQL query suite (e.g., code-scanning, security-extended, security-and-quality)")
    parser.add_argument("--codeql-timeout-seconds", type=int, help="Override CodeQL analyze timeout seconds")
    parser.add_argument("--codeql-languages", type=str, help="Comma-separated CodeQL languages to target (e.g., python,java). Defaults to auto-detect when omitted")
    parser.add_argument("--codeql-skip-autobuild", action="store_true", help="Skip CodeQL autobuild for compiled languages (useful when build pipelines are absent)")
    parser.add_argument("--codeql-recreate-db", action="store_true", help="Recreate CodeQL DBs before analysis (avoids cache issues)")
    parser.add_argument("--scanners-parallel", type=int, default=1, help="How many scanners to run in parallel")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first hard error (exit code not in {0,1})")

    # Allow opting out of deep-mode escalations per scanner
    parser.add_argument("--no-deep-codeql", action="store_true", help="In deep profile, do not recreate CodeQL DBs")
    parser.add_argument("--no-deep-terraform", action="store_true", help="In deep profile, do not run trivy fs")
    parser.add_argument("--no-deep-contributors", action="store_true", help="In deep profile, do not compute churn/PR metrics")

    # Pass-through flags for hardcoded_ips
    parser.add_argument("--ignore-private", action="store_true", help="Pass through to hardcoded_ips to ignore private-scope IPs")
    parser.add_argument("--ignore-localhost", action="store_true", help="Pass through to hardcoded_ips to ignore localhost/loopback/unspecified")
    parser.add_argument("--ignore-example", action="store_true", help="Pass through to hardcoded_ips to ignore example IP ranges and example.* domains")

    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (repeatable)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress orchestrator output (still logs to files)")

    parser.add_argument("--dry-run", action="store_true", help="Print planned commands and exit")

    args = parser.parse_args(argv)

    if args.quiet:
        # Keep at least 0
        args.verbose = 0
    return args


if __name__ == "__main__":
    ns = parse_args()
    try:
        rc = run_orchestrator(ns)
        sys.exit(rc)
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except SystemExit as e:
        # Allow our explicit SystemExit to propagate code
        raise
    except Exception as e:
        print(f"Unexpected error in orchestrator: {e}", file=sys.stderr)
        sys.exit(1)
