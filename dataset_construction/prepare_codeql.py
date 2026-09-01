"""
prepare_codeql.py

Extract generated Python code from res_*.jsonl files, syntax-validate each
snippet, append the CWE-specific CodeQL entry-point wrapper, and write
organised directories ready for CodeQL analysis.

Output layout:
  data/codeql/<mode>/<prompt_type>/cwe-XXX/<record_id>__gen<idx>.py

  mode          sampling | greedy
  prompt_type   safe | vuln | vuln_generic
  cwe-XXX       one subdirectory per target CWE (5 CWEs)

Per-CWE wrapper strategy (applied to ALL snippets regardless of the
question's cwe_id, because a snippet may be vulnerable to a CWE it was
not designed for):
  cwe-022  args_string          (PathInjection — taint-tracking)
  cwe-079  args_string_direct   (ReflectedXSS  — must NOT wrap return in str())
  cwe-089  args_string          (SqlInjection  — taint-tracking)
  cwe-094  args_string          (CodeInjection — taint-tracking)
  cwe-295  no wrapper           (MissingHostKeyValidation — structural)
  (cwe-327 removed — dynamic getattr dispatch undetectable by static analysis)
  cwe-502  bytes_first          (UnsafeDeserialization — taint-tracking)

Syntax validation:
  ast.parse() is called on the raw extracted code BEFORE the wrapper is
  appended.  Snippets that fail are skipped for ALL CWEs; they are logged
  in data/codeql/<mode>/<prompt_type>/invalid_code.jsonl for audit.

Usage:
  python prepare_codeql.py                          # all modes, all groups, all CWEs
  python prepare_codeql.py --mode sampling          # sampling only
  python prepare_codeql.py --prompt_type vuln       # vuln group only
  python prepare_codeql.py --cwe cwe-089 cwe-022    # subset of CWEs
  python prepare_codeql.py --dry_run                # report counts without writing
"""
# --- repo path setup: allow running this script from any directory ---
import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parents[1]
for _d in ("common", "dataset_construction"):
    _p = _REPO_ROOT / _d
    if _p.is_dir() and str(_p) not in _sys.path:
        _sys.path.insert(0, str(_p))
# ---------------------------------------------------------------------

import ast
import argparse
import json
import re
import sys
import warnings
from pathlib import Path

from codeql_entry_points import add_entry_point

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data"

ALL_CWES = ["cwe-022", "cwe-079", "cwe-094", "cwe-295", "cwe-502"]

# Source JSONL files for each (mode, prompt_type) combination.
# Files within a prompt_type are non-overlapping parts of the same record set.
SOURCES = {
    "sampling": {
        "safe": [
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_part1.jsonl",
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_part2.jsonl",
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_part3.jsonl",
        ],
        "vuln": [
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln.jsonl",
        ],
        "vuln_generic": [
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln_generic_part1.jsonl",
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln_generic_part2.jsonl",
            "code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln_generic_part3.jsonl",
        ],
    },
    "greedy": {
        "safe": [
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_greedy_part1.jsonl",
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_greedy_part2.jsonl",
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_greedy_part3.jsonl",
        ],
        "vuln": [
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_greedy.jsonl",
        ],
        "vuln_generic": [
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_generic_greedy_part1.jsonl",
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_generic_greedy_part2.jsonl",
            "code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_generic_greedy_part3.jsonl",
        ],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:python)?\s*\n?(.*?)\n?```", re.DOTALL)


def strip_fences(text: str) -> str:
    """Remove ```python … ``` or ``` … ``` markdown fences."""
    m = _FENCE_RE.search(text)
    return m.group(1).strip() if m else text.strip()


def syntax_check(code: str) -> tuple[bool, str]:
    """
    Return (is_valid, error_message).
    Validates the raw extracted code (without wrapper) using ast.parse.
    SyntaxWarnings (e.g. invalid escape sequences in regex strings) are
    suppressed — they do not make code unparseable and CodeQL handles them.
    An empty string is treated as invalid.
    """
    if not code:
        return False, "empty"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, f"SyntaxError at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------

def process_group(
    mode: str,
    prompt_type: str,
    cwes: list[str],
    dry_run: bool,
    verbose: bool,
) -> dict:
    """
    Process all source JSONL files for (mode, prompt_type).
    Writes one .py file per (snippet, cwe) into data/codeql/<mode>/<prompt_type>/cwe-XXX/.
    Returns a stats dict.
    """
    src_paths = [DATA / rel for rel in SOURCES[mode][prompt_type]]
    out_root = DATA / "codeql" / mode / prompt_type

    # Initialise stats
    stats: dict = {
        "records_seen": 0,
        "records_skipped_json": 0,
        "snippets_total": 0,
        "snippets_invalid_syntax": 0,
        "snippets_empty": 0,
    }
    for cwe in cwes:
        stats[cwe] = {"written": 0}

    invalid_log: list[dict] = []

    if not dry_run:
        for cwe in cwes:
            (out_root / cwe).mkdir(parents=True, exist_ok=True)

    seen_record_ids: set[str] = set()

    for src_path in src_paths:
        if not src_path.exists():
            print(f"  [WARN] Source not found, skipping: {src_path}", file=sys.stderr)
            continue

        with open(src_path, encoding="utf-8") as fh:
            for lineno, raw_line in enumerate(fh, 1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    stats["records_skipped_json"] += 1
                    print(f"  [WARN] JSON error in {src_path.name}:{lineno}: {exc}", file=sys.stderr)
                    continue

                record_id = record.get("id", "")
                if not record_id:
                    stats["records_skipped_json"] += 1
                    continue
                if record_id in seen_record_ids:
                    continue
                seen_record_ids.add(record_id)
                stats["records_seen"] += 1

                predicted = record.get("predicted_code", [])
                # Normalise: always a list
                if isinstance(predicted, str):
                    predicted = [predicted]

                for gen_idx, raw_code in enumerate(predicted):
                    stats["snippets_total"] += 1

                    code = strip_fences(raw_code)

                    valid, err = syntax_check(code)
                    if not valid:
                        if not code:
                            stats["snippets_empty"] += 1
                        else:
                            stats["snippets_invalid_syntax"] += 1
                        invalid_log.append({
                            "record_id": record_id,
                            "gen_idx": gen_idx,
                            "error": err,
                        })
                        continue  # skip this snippet for all CWEs

                    # Write one file per CWE with the appropriate wrapper
                    filename = f"{record_id}__gen{gen_idx}.py"
                    for cwe in cwes:
                        wrapped = add_entry_point(code, cwe)
                        out_path = out_root / cwe / filename
                        if not dry_run:
                            out_path.write_text(wrapped, encoding="utf-8")
                        stats[cwe]["written"] += 1

    # Persist invalid log once per (mode, prompt_type)
    if invalid_log:
        log_path = out_root / "invalid_code.jsonl"
        if not dry_run:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "w", encoding="utf-8") as fh:
                for entry in invalid_log:
                    fh.write(json.dumps(entry) + "\n")
        if verbose:
            print(f"  Invalid log: {log_path.relative_to(BASE)} ({len(invalid_log)} entries)")

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _print_stats(mode: str, prompt_type: str, stats: dict, cwes: list[str], dry_run: bool) -> None:
    tag = " [DRY RUN]" if dry_run else ""
    print(f"\n  {mode}/{prompt_type}{tag}")
    print(f"    records : {stats['records_seen']:>7}  (JSON-skipped: {stats['records_skipped_json']})")
    total_snip = stats["snippets_total"]
    n_invalid  = stats["snippets_invalid_syntax"] + stats["snippets_empty"]
    print(f"    snippets: {total_snip:>7}  invalid={n_invalid} "
          f"(syntax_err={stats['snippets_invalid_syntax']}, empty={stats['snippets_empty']})")
    for cwe in cwes:
        w = stats[cwe]["written"]
        print(f"    {cwe}: {w:>7} files written")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and wrap generated code into CodeQL-ready .py files."
    )
    parser.add_argument(
        "--mode", choices=["sampling", "greedy", "all"], default="all",
        help="Which generation mode to process (default: all)",
    )
    parser.add_argument(
        "--prompt_type", choices=["safe", "vuln", "vuln_generic", "all"], default="all",
        help="Which prompt group to process (default: all)",
    )
    parser.add_argument(
        "--cwe", nargs="*", default=ALL_CWES,
        metavar="CWE_ID",
        help="CWE IDs to prepare (default: all 5). E.g. --cwe cwe-089 cwe-022",
    )
    parser.add_argument(
        "--dry_run", action="store_true",
        help="Compute and print stats without writing any files",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-CWE detail lines",
    )
    args = parser.parse_args()

    modes         = ["sampling", "greedy"] if args.mode == "all" else [args.mode]
    prompt_types  = ["safe", "vuln", "vuln_generic"] if args.prompt_type == "all" else [args.prompt_type]
    cwes          = args.cwe
    verbose       = not args.quiet

    unknown = [c for c in cwes if c not in ALL_CWES]
    if unknown:
        print(f"ERROR: unknown CWE IDs: {unknown}\nValid: {ALL_CWES}", file=sys.stderr)
        sys.exit(1)

    print(f"Modes        : {modes}")
    print(f"Prompt types : {prompt_types}")
    print(f"CWEs         : {cwes}")
    print(f"Output root  : {(DATA / 'codeql').relative_to(BASE)}")
    if args.dry_run:
        print("** DRY RUN — no files will be written **")

    grand_total: dict[str, int] = {cwe: 0 for cwe in cwes}
    grand_invalid = 0

    for mode in modes:
        for pt in prompt_types:
            stats = process_group(mode, pt, cwes, args.dry_run, verbose)
            if verbose:
                _print_stats(mode, pt, stats, cwes, args.dry_run)
            for cwe in cwes:
                grand_total[cwe] += stats[cwe]["written"]
            grand_invalid += stats["snippets_invalid_syntax"] + stats["snippets_empty"]

    print("\n--- Grand totals ---")
    print(f"  Syntax-invalid snippets skipped: {grand_invalid}")
    for cwe in cwes:
        print(f"  {cwe}: {grand_total[cwe]:>8} files total")

    if not args.dry_run:
        print(f"\nFiles written under: {(DATA / 'codeql').resolve()}")


if __name__ == "__main__":
    main()
