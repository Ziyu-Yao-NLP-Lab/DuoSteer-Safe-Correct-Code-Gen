"""
Run CodeQL detection on all steering condition folders and compute per-condition
detection rates.

Strategy: one CodeQL database per CWE, source-root = results/codeql_for_detection/cwe-XXX/
All condition subdirectories are included; SARIF file URIs encode the condition name
as the first path component (e.g. root__baseline/seccodeplt_22_0.py).

Two analyses per CWE:
  1. Target-CWE queries  → target_detection_rate
  2. python-security-extended.qls suite → all_detection_rate
     other_detection_rate = all_detection_rate - target_detection_rate

Output:
  results/codeql_detection/
    cwe-022/
      detection_results.json   -- per-condition rates (target / all / other)
      issues_target.sarif      -- raw SARIF for target queries
      issues_all.sarif         -- raw SARIF for all-security suite
      issues_target.json       -- parsed target SARIF
      issues_all.json          -- parsed all-security SARIF
    ...
    summary.json               -- all CWEs in one place

Usage:
    python run_codeql_detection.py [--cwe cwe-022 ...] [--dry_run] [--codeql /path/to/codeql]
    python run_codeql_detection.py --source_base path/to/sources [--out_base path/to/out]
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

CODEQL_DEFAULT = os.environ.get("CODEQL_BIN", "codeql")
QLPACK_BASE = os.environ.get("CODEQL_QLPACK", "")
SUITE_ALL = os.environ.get("CODEQL_SUITE_ALL", "")

SOURCE_BASE = Path("results/codeql_for_detection")
DB_BASE = Path("results/codeql_detection/_databases")
OUT_BASE = Path("results/codeql_detection")

FORMAT_SCRIPT = Path(__file__).resolve().parent / "format_output_new.py"

# CWE → list of .ql file paths (relative to QLPACK_BASE)
CWE_QUERIES = {
    "cwe-022": ["CWE-022/PathInjection.ql", "CWE-022/TarSlip.ql"],
    "cwe-079": ["CWE-079/ReflectedXss.ql"],
    "cwe-094": ["CWE-094/CodeInjection.ql"],
    "cwe-295": ["CWE-295/MissingHostKeyValidation.ql", "CWE-295/RequestWithoutValidation.ql"],
    "cwe-502": ["CWE-502/UnsafeDeserialization.ql"],
}

# cwe-327 removed: generated code uses getattr(hashlib, algo_name)() — dynamic dispatch
# that CodeQL cannot resolve statically. Detection rate is 0% by construction.
ALL_CWES = ["cwe-022", "cwe-079", "cwe-094", "cwe-295", "cwe-502"]


def run(cmd, dry_run=False, check=True):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    if dry_run:
        return None
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"  STDERR: {result.stderr[-2000:]}", file=sys.stderr)
        raise RuntimeError(f"Command failed (exit {result.returncode})")
    return result


def build_database(codeql, cwe_id, source_dir, db_dir, dry_run):
    """Build CodeQL Python database from source_dir."""
    print(f"\n[{cwe_id}] Building database from {source_dir} -> {db_dir}")
    if not dry_run:
        db_dir.mkdir(parents=True, exist_ok=True)
    run([
        codeql, "database", "create", str(db_dir),
        "--language=python",
        f"--source-root={source_dir}",
        "--overwrite",
    ], dry_run=dry_run)


def run_analysis(codeql, cwe_id, db_dir, query_paths, sarif_out, dry_run):
    """Run CodeQL analysis with given queries, output SARIF."""
    print(f"\n[{cwe_id}] Running analysis -> {sarif_out}")
    if not dry_run:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
    run([
        codeql, "database", "analyze", str(db_dir),
        *[str(q) for q in query_paths],
        "--format=sarifv2.1.0",
        f"--output={sarif_out}",
        "--no-print-metrics-summary",
    ], dry_run=dry_run)


def parse_sarif(sarif_path, out_json_path, dry_run, source_dir=None):
    """Convert SARIF to structured JSON via format_output_new.py.

    source_dir: when provided (and cwe is not cwe-079), passes --source_dir to
    filter findings whose startLine falls inside the CodeQL entry-point wrapper.
    cwe-079 must NOT use this filter: its XSS sink (make_response) is inside the
    wrapper by design, so filtering would remove all valid detections.
    """
    print(f"  Parsing SARIF -> {out_json_path}")
    if dry_run:
        return
    cmd = [sys.executable, str(FORMAT_SCRIPT), "-i", str(sarif_path), "-o", str(out_json_path)]
    if source_dir is not None:
        cmd += ["--source_dir", str(source_dir)]
    run(cmd, dry_run=False)


def _load_detected_files(json_path) -> set:
    """Return set of relative file URIs that have at least one detection."""
    with open(json_path) as f:
        data = json.load(f)
    detected = set()
    for result in data.get("Results", []):
        uri = result.get("fileName", "")
        if uri:
            detected.add(uri.lstrip("/"))
    return detected


def compute_detection_rates(source_dir, target_json, all_json=None, dry_run=False):
    """
    Compute per-condition detection rates from parsed SARIF JSON files.

    Returns dict: condition_name -> {
        n_files, n_target, target_rate,
        n_all, all_rate, n_other, other_rate   (only when all_json provided)
    }
    """
    if dry_run:
        return {}

    target_files = _load_detected_files(target_json)
    all_files = _load_detected_files(all_json) if all_json else None

    detection = {}
    for cond_dir in sorted(source_dir.iterdir()):
        if not cond_dir.is_dir():
            continue
        cond_name = cond_dir.name
        py_files = list(cond_dir.glob("*.py"))
        n_total = len(py_files)

        n_target = sum(1 for p in py_files if f"{cond_name}/{p.name}" in target_files)
        entry = {
            "n_files": n_total,
            "n_target": n_target,
            "target_rate": round(n_target / n_total, 4) if n_total else 0.0,
        }

        if all_files is not None:
            n_all = sum(1 for p in py_files if f"{cond_name}/{p.name}" in all_files)
            n_other = n_all - n_target
            entry.update({
                "n_all": n_all,
                "all_rate": round(n_all / n_total, 4) if n_total else 0.0,
                "n_other": max(0, n_other),
                "other_rate": round(max(0, n_other) / n_total, 4) if n_total else 0.0,
            })

        detection[cond_name] = entry

    return detection


def process_cwe(codeql, cwe_id, source_base, db_base, out_base, run_all_suite, dry_run):
    source_dir = source_base / cwe_id
    if not source_dir.is_dir():
        print(f"[{cwe_id}] Source dir not found: {source_dir} — skipping")
        return None

    db_dir = db_base / cwe_id
    out_dir = out_base / cwe_id
    sarif_target = out_dir / "issues_target.sarif"
    json_target = out_dir / "issues_target.json"
    sarif_all = out_dir / "issues_all.sarif"
    json_all = out_dir / "issues_all.json"
    results_path = out_dir / "detection_results.json"

    query_paths = [Path(QLPACK_BASE) / rel for rel in CWE_QUERIES[cwe_id]]
    missing = [q for q in query_paths if not q.exists()]
    if missing:
        print(f"[{cwe_id}] Missing query files: {missing}")
        return None
    if run_all_suite and not Path(SUITE_ALL).exists():
        print(f"[{cwe_id}] All-security suite not found: {SUITE_ALL}")
        return None

    # Step 1: build database (shared by both analyses)
    build_database(codeql, cwe_id, source_dir, db_dir, dry_run)

    # cwe-079: do NOT pass source_dir — XSS sink (make_response) is in the wrapper
    # by design; filtering would remove all valid detections. CodeQL's sanitizer
    # recognition (html.escape etc.) handles false positives instead.
    # All other CWEs: pass source_dir so wrapper-only findings are excluded.
    filter_dir = None if cwe_id == "cwe-079" else source_dir

    # Step 2a: target-CWE analysis
    run_analysis(codeql, cwe_id, db_dir, query_paths, sarif_target, dry_run)
    parse_sarif(sarif_target, json_target, dry_run, source_dir=filter_dir)

    # Step 2b: all-security suite analysis
    if run_all_suite:
        run_analysis(codeql, cwe_id, db_dir, [Path(SUITE_ALL)], sarif_all, dry_run)
        parse_sarif(sarif_all, json_all, dry_run, source_dir=filter_dir)

    # Step 3: compute per-condition detection rates
    all_json_arg = json_all if run_all_suite else None
    detection = compute_detection_rates(source_dir, json_target, all_json_arg, dry_run)

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(results_path, "w") as f:
            json.dump({"cwe": cwe_id, "conditions": detection}, f, indent=2)
        print(f"\n[{cwe_id}] Detection rates written to {results_path}")

        # Print summary table
        has_all = run_all_suite
        hdr = f"  {'Condition':<55} {'n_files':>7} {'n_tgt':>6} {'tgt%':>6}"
        if has_all:
            hdr += f" {'n_all':>6} {'all%':>6} {'other%':>7}"
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        for cond, v in sorted(detection.items()):
            row = (f"  {cond:<55} {v['n_files']:>7} {v['n_target']:>6}"
                   f" {v['target_rate']:>6.1%}")
            if has_all:
                row += (f" {v['n_all']:>6} {v['all_rate']:>6.1%}"
                        f" {v['other_rate']:>7.1%}")
            print(row)

    return detection


def main():
    parser = argparse.ArgumentParser(
        description="Run CodeQL detection on all steering conditions."
    )
    parser.add_argument("--cwe", nargs="*", default=ALL_CWES,
                        help="CWE IDs to process (default: all 5)")
    parser.add_argument("--no_all_suite", action="store_true",
                        help="Skip all-security suite analysis (target CWE only)")
    parser.add_argument("--qlpack_base", default=None,
                        help="Path to the CodeQL python-queries Security directory (default: $CODEQL_QLPACK)")
    parser.add_argument("--suite_all", default=None,
                        help="Path to the python-security-extended.qls suite (default: $CODEQL_SUITE_ALL)")
    parser.add_argument("--codeql", default=CODEQL_DEFAULT,
                        help="Path to codeql binary")
    parser.add_argument("--dry_run", action="store_true",
                        help="Print commands without running them")
    parser.add_argument("--source_base", default=None,
                        help="Custom source root (default: results/codeql_for_detection)")
    parser.add_argument("--db_base", default=None,
                        help="Custom CodeQL database root (optional)")
    parser.add_argument("--out_base", default=None,
                        help="Custom detection output root (optional)")
    args = parser.parse_args()
    global QLPACK_BASE, SUITE_ALL
    if args.qlpack_base:
        QLPACK_BASE = args.qlpack_base
    if args.suite_all:
        SUITE_ALL = args.suite_all

    if not Path(args.codeql).exists():
        print(f"ERROR: codeql binary not found at {args.codeql}")
        sys.exit(1)

    source_base = SOURCE_BASE
    db_base = DB_BASE
    out_base = OUT_BASE

    if args.source_base:
        source_base = Path(args.source_base)
    if args.db_base:
        db_base = Path(args.db_base)
    if args.out_base:
        out_base = Path(args.out_base)

    run_all_suite = not args.no_all_suite

    all_results = {}
    for cwe_id in args.cwe:
        detection = process_cwe(
            args.codeql, cwe_id, source_base, db_base, out_base, run_all_suite, args.dry_run
        )
        if detection is not None:
            all_results[cwe_id] = detection

    if not args.dry_run and all_results:
        summary_path = out_base / "summary.json"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    main()
