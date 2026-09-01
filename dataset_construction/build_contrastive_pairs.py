"""
Build two contrastive (safe, vulnerable) pair datasets per (question, CWE).

Pairing rules (enforced in this script unless noted):
  1. Vulnerable code findings must be in the generated function body, NOT the
     CodeQL entry-point wrapper. Enforced upstream: format_output_new.py must be
     run with --source_dir so wrapper-only findings are excluded from *_issues.json
     before this script reads them.
     Exception: cwe-079 — the XSS sink (make_response) is necessarily in the
     wrapper; format_output_new.py must be run WITHOUT --source_dir for cwe-079.
  2. No duplicate code within a (record_id, CWE): pairs are deduplicated by MD5
     hash of the raw response text.
  3. Safe code must be syntax-error free. Enforced by only considering gen indices
     that appear as .py files in the CodeQL source directory (prepare_codeql.py
     runs ast.parse() before writing any file).
  4. Number of pairs equals the number of unique vulnerable code snippets identified
     (one pair per unique vulnerable gen, across all records and CWEs).
  5. Safe code may be reused across pairs only when there are fewer clean safe gens
     than vulnerable gens for the same (record_id, CWE). The safe pool is cycled
     round-robin in that case.
  6. Safe and vulnerable code in each pair come from the same question (record_id).
  7. safe_only: both sides come from the benign (safe) prompt group; variation
     arises from stochastic sampling differences across generations.
  8. cross_group: vulnerable side from vuln or vuln_generic prompt; safe side
     from the benign (safe) prompt, same record_id.

Each gen is tagged only with the TARGET CWE ID for the query that detected it
(e.g. cwe-022, not the related sub-CWEs cwe-023/036/073). This avoids inflating
pair counts with taxonomically-related CWEs that map to the same vulnerability.

Output:
  data/contrastive_pairs/contrastive_pairs_safe_only_<mode>.jsonl
  data/contrastive_pairs/contrastive_pairs_cross_group_<mode>.jsonl

Usage:
  python build_contrastive_pairs.py --mode sampling
  python build_contrastive_pairs.py --mode greedy
  python build_contrastive_pairs.py --mode sampling --cwe cwe-022 cwe-079
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict, Counter
from itertools import cycle
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[1]

ALL_CWES = ["cwe-022", "cwe-079", "cwe-094", "cwe-295", "cwe-502"]

RES_FILES = {
    "sampling": {
        "safe": [
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_part1.jsonl",
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_part2.jsonl",
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_part3.jsonl",
        ],
        "vuln": [
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln.jsonl",
        ],
        "vuln_generic": [
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln_generic_part1.jsonl",
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln_generic_part2.jsonl",
            "data/code_gen_results_sampling/res_code_gen_combined_no_seccodeplt_vuln_generic_part3.jsonl",
        ],
    },
    "greedy": {
        "safe": [
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_greedy_part1.jsonl",
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_greedy_part2.jsonl",
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_greedy_part3.jsonl",
        ],
        "vuln": [
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_greedy.jsonl",
        ],
        "vuln_generic": [
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_generic_greedy_part1.jsonl",
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_generic_greedy_part2.jsonl",
            "data/code_gen_results_greedy/res_code_gen_combined_no_seccodeplt_vuln_generic_greedy_part3.jsonl",
        ],
    },
}

GROUP_SPECIFIC_FIELDS = {"messages", "vulnerability_type", "vulnerability_description"}
EXCLUDE_FIELDS = {"predicted_code"}

# gen_idx -> {cwes: set[str], detections: list[dict]}
GenFindings = dict[int, dict]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def response_hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def make_gen_entry(
    rec: dict,
    group: str,
    gen_idx: int,
    raw: str,
    codeql_detections: list[dict] | None = None,
) -> dict:
    entry = {"group": group, "gen_index": gen_idx, "response": raw}
    if codeql_detections is not None:
        entry["codeql_detections"] = codeql_detections
    entry.update({k: v for k, v in rec.items() if k in GROUP_SPECIFIC_FIELDS})
    return entry


def make_pair(shared_meta: dict, cwe_id: str, safe_entry: dict, vuln_entry: dict) -> dict:
    """Assemble one flat pair record from the two gen entries.

    Pair records store code only; user prompts are reconstructed at runtime
    from the question by the pipeline scripts (see extract_representations.py
    --prompt_mode).
    """
    return {
        **shared_meta,
        "cwe_id": cwe_id,
        "safe_code": safe_entry["response"],
        "vuln_code": vuln_entry["response"],
        "vuln_codeql_detections": vuln_entry.get("codeql_detections", []),
    }


def detections_for_cwe(detections: list[dict], cwe_id: str) -> list[dict]:
    return [d for d in detections if cwe_id in d.get("cweIds", [])]


def build_shared_meta(rec: dict) -> dict:
    """Extract shared metadata; drop the source dataset's cwe_id (the pair's
    cwe_id is set from the CodeQL detection, not the question's nominal CWE)."""
    meta = {
        k: v for k, v in rec.items()
        if k not in GROUP_SPECIFIC_FIELDS and k not in {"responses", "cwe_id"} | EXCLUDE_FIELDS
    }
    return meta


# --------------------------------------------------------------------------- #
# Step 1: Load CodeQL findings per group
# --------------------------------------------------------------------------- #

def load_findings(codeql_base: Path, cwe_ids: list[str]) -> dict[str, GenFindings]:
    """
    Returns findings[record_id][gen_idx] = {
        "cwes":       set of TARGET cwe_ids detected in this gen,
        "detections": list of detection dicts from all triggered queries,
    }

    Only gen indices that appear as .py files in the CodeQL source directories
    are included (Rule 3: syntax-error-free guarantee from prepare_codeql.py).

    Each gen is tagged with the TARGET CWE ID only (e.g. "cwe-022"), not
    sub-CWEs like "cwe-023". This prevents pair-count inflation from
    taxonomically-related CWEs.

    Requires format_output_new.py to have been run with --source_dir so that
    wrapper-induced false positives are already excluded from *_issues.json
    (Rule 1).
    """
    # Determine syntax-valid gen indices from the first available CWE dir.
    # All CWE dirs contain the same files (prepare_codeql.py writes each
    # syntax-valid gen to every CWE dir).
    written: dict[str, set[int]] = defaultdict(set)
    for cwe_id in cwe_ids:
        cwe_dir = codeql_base / cwe_id
        if cwe_dir.is_dir():
            for py_file in cwe_dir.glob("*.py"):
                m = re.match(r"(.+)__gen(\d+)\.py$", py_file.name)
                if m:
                    written[m.group(1)].add(int(m.group(2)))
            break  # one dir is sufficient

    if not written:
        print(f"  [WARN] No .py files found under {codeql_base}", file=sys.stderr)

    # Load per-CWE detection results and merge.
    raw_det: dict[str, dict[int, dict]] = {}

    for cwe_id in cwe_ids:
        json_path = codeql_base / f"{cwe_id}_issues.json"
        if not json_path.exists():
            print(f"  [WARN] Missing findings: {json_path}", file=sys.stderr)
            continue
        with open(json_path) as f:
            issues = json.load(f)
        for e in issues.get("Results", []):
            fname = Path(e["fileName"]).name
            m = re.match(r"(.+)__gen(\d+)\.py$", fname)
            if not m:
                continue
            rid, gen_idx = m.group(1), int(m.group(2))
            if rid not in raw_det:
                raw_det[rid] = {}
            if gen_idx not in raw_det[rid]:
                raw_det[rid][gen_idx] = {"cwes": set(), "detections": []}
            # Tag with TARGET cwe_id only (not sub-CWEs)
            raw_det[rid][gen_idx]["cwes"].add(cwe_id)
            raw_det[rid][gen_idx]["detections"].extend(e.get("CWEs", []))

    # Build final findings dict restricted to syntax-valid gens (Rule 3)
    findings: dict[str, GenFindings] = {}
    for rid, gen_set in written.items():
        findings[rid] = {}
        for gen_idx in sorted(gen_set):
            if rid in raw_det and gen_idx in raw_det[rid]:
                findings[rid][gen_idx] = raw_det[rid][gen_idx]
            else:
                findings[rid][gen_idx] = {"cwes": set(), "detections": []}

    return findings


# --------------------------------------------------------------------------- #
# Step 2: Load res files — metadata + raw responses
# --------------------------------------------------------------------------- #

def load_res_data(mode: str) -> dict[str, dict[str, dict]]:
    """
    Returns res_data[group][record_id] = {
        ...record fields minus predicted_code...,
        "responses": list[str]   (raw predicted_code entries)
    }
    """
    res_data: dict[str, dict[str, dict]] = {}
    for group, file_list in RES_FILES[mode].items():
        group_records: dict[str, dict] = {}
        for fname in file_list:
            fpath = BASE / fname
            if not fpath.exists():
                print(f"  [WARN] Missing: {fpath}", file=sys.stderr)
                continue
            with open(fpath) as f:
                for line in f:
                    d = json.loads(line)
                    rid = d["id"]
                    if rid in group_records:
                        continue
                    record = {k: v for k, v in d.items() if k not in EXCLUDE_FIELDS}
                    predicted = d.get("predicted_code", [])
                    record["responses"] = predicted if isinstance(predicted, list) else [predicted]
                    group_records[rid] = record
        res_data[group] = group_records
    return res_data


# --------------------------------------------------------------------------- #
# Step 3a: safe-only pairs (both sides from 'safe' prompt group, Rule 7)
# --------------------------------------------------------------------------- #

def build_safe_only_pairs(
    safe_findings: dict[str, GenFindings],
    res_data: dict[str, dict[str, dict]],
) -> list[dict]:
    safe_records = res_data["safe"]
    pairs = []

    for record_id in sorted(safe_records.keys()):
        rec = safe_records[record_id]
        shared_meta = build_shared_meta(rec)
        responses = rec["responses"]
        gen_findings = safe_findings.get(record_id, {})

        # CWEs triggered in any safe gen for this record
        all_cwes: set[str] = set()
        for entry in gen_findings.values():
            all_cwes.update(entry["cwes"])
        if not all_cwes:
            continue

        for cwe_id in sorted(all_cwes):
            # Vulnerable side: safe-group gens where this CWE is detected (Rule 7)
            vuln_gens: list[dict] = []
            seen_vuln: set[str] = set()
            for gen_idx, entry in sorted(gen_findings.items()):
                if cwe_id not in entry["cwes"] or gen_idx >= len(responses):
                    continue
                raw = responses[gen_idx]
                h = response_hash(raw)
                if h in seen_vuln:  # Rule 2: no duplicates
                    continue
                seen_vuln.add(h)
                vuln_gens.append(make_gen_entry(
                    rec, "safe", gen_idx, raw,
                    codeql_detections=detections_for_cwe(entry["detections"], cwe_id),
                ))

            if not vuln_gens:
                continue

            # Safe side: safe-group gens where this CWE is NOT detected (Rule 6+7)
            safe_gens: list[dict] = []
            seen_safe: set[str] = set()
            for gen_idx, entry in sorted(gen_findings.items()):
                if cwe_id in entry["cwes"] or gen_idx >= len(responses):
                    continue
                raw = responses[gen_idx]
                h = response_hash(raw)
                if h in seen_safe:  # Rule 2
                    continue
                seen_safe.add(h)
                safe_gens.append(make_gen_entry(rec, "safe", gen_idx, raw))

            if not safe_gens:
                continue

            # Rule 4: one pair per unique vulnerable gen
            # Rule 5: cycle safe gens (reuse only when pool is exhausted)
            safe_pool = cycle(safe_gens)
            for vuln_entry in vuln_gens:
                pairs.append(make_pair(shared_meta, cwe_id, next(safe_pool), vuln_entry))

    return pairs


# --------------------------------------------------------------------------- #
# Step 3b: cross-group pairs (vuln/vuln_generic → safe, Rule 8)
# --------------------------------------------------------------------------- #

def build_cross_group_pairs(
    all_findings: dict[str, dict[str, GenFindings]],
    res_data: dict[str, dict[str, dict]],
) -> list[dict]:
    VULN_GROUPS = ["vuln", "vuln_generic"]

    all_record_ids: set[str] = set()
    for g in VULN_GROUPS:
        all_record_ids.update(res_data[g].keys())

    pairs = []

    for record_id in sorted(all_record_ids):
        # Safe side must exist (Rule 6+8)
        safe_rec = res_data["safe"].get(record_id)
        if not safe_rec:
            continue
        safe_responses = safe_rec["responses"]
        safe_gen_findings = all_findings["safe"].get(record_id, {})

        shared_meta = build_shared_meta(safe_rec)

        # CWEs detected in any vuln/vuln_generic gen for this record (Rule 8)
        all_cwes: set[str] = set()
        for g in VULN_GROUPS:
            for entry in all_findings[g].get(record_id, {}).values():
                all_cwes.update(entry["cwes"])
        if not all_cwes:
            continue

        for cwe_id in sorted(all_cwes):
            # Vulnerable side: vuln/vuln_generic gens where this CWE is detected
            vuln_gens: list[dict] = []
            seen_vuln: set[str] = set()
            for g in VULN_GROUPS:
                rec = res_data[g].get(record_id)
                if not rec:
                    continue
                responses = rec["responses"]
                for gen_idx, entry in sorted(all_findings[g].get(record_id, {}).items()):
                    if cwe_id not in entry["cwes"] or gen_idx >= len(responses):
                        continue
                    raw = responses[gen_idx]
                    h = response_hash(raw)
                    if h in seen_vuln:  # Rule 2
                        continue
                    seen_vuln.add(h)
                    vuln_gens.append(make_gen_entry(
                        rec, g, gen_idx, raw,
                        codeql_detections=detections_for_cwe(entry["detections"], cwe_id),
                    ))

            if not vuln_gens:
                continue

            # Safe side: safe-group gens where this CWE is NOT detected (Rule 3+6+8)
            safe_gens: list[dict] = []
            seen_safe: set[str] = set()
            for gen_idx, entry in sorted(safe_gen_findings.items()):
                if cwe_id in entry["cwes"] or gen_idx >= len(safe_responses):
                    continue
                raw = safe_responses[gen_idx]
                h = response_hash(raw)
                if h in seen_safe:  # Rule 2
                    continue
                seen_safe.add(h)
                safe_gens.append(make_gen_entry(safe_rec, "safe", gen_idx, raw))

            if not safe_gens:
                continue

            # Rule 4+5
            safe_pool = cycle(safe_gens)
            for vuln_entry in vuln_gens:
                pairs.append(make_pair(shared_meta, cwe_id, next(safe_pool), vuln_entry))

    return pairs


# --------------------------------------------------------------------------- #
# Diversity cap (applied per CWE when that CWE's pair count exceeds threshold)
# --------------------------------------------------------------------------- #

def apply_diversity_cap(
    pairs: list[dict],
    max_per_question: int,
    threshold: int = 2000,
) -> list[dict]:
    """
    For each CWE whose pair count exceeds `threshold`, limit each question
    (record_id) to at most `max_per_question` pairs for that CWE.

    CWEs below the threshold are left untouched — no diversity cap is needed
    when the total is already small.

    Pairs are kept in their original order (first N per question per CWE).
    """
    cwe_counts = Counter(p["cwe_id"] for p in pairs)
    capped_cwes = {cwe for cwe, cnt in cwe_counts.items() if cnt > threshold}

    if not capped_cwes:
        return pairs

    per_question: dict[tuple, int] = defaultdict(int)
    result = []
    for pair in pairs:
        cwe_id = pair["cwe_id"]
        if cwe_id not in capped_cwes:
            result.append(pair)
            continue
        key = (pair["id"], cwe_id)
        if per_question[key] < max_per_question:
            per_question[key] += 1
            result.append(pair)

    return result


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def print_stats(label: str, pairs: list[dict]) -> None:
    print(f"\n[{label}] {len(pairs)} pairs total")
    cwe_counts = Counter(p["cwe_id"] for p in pairs)
    print("  By CWE:")
    for cwe, cnt in sorted(cwe_counts.items()):
        print(f"    {cwe}: {cnt}")


def main():
    parser = argparse.ArgumentParser(
        description="Build safe/vulnerable contrastive pairs from CodeQL findings."
    )
    parser.add_argument(
        "--mode", choices=["sampling", "greedy"], default="sampling",
        help="Generation mode (default: sampling)",
    )
    parser.add_argument(
        "--cwe", nargs="*", default=ALL_CWES,
        metavar="CWE_ID",
        help="CWE IDs to include (default: all 6)",
    )
    parser.add_argument(
        "--max_pairs_per_question", type=int, default=3,
        help=(
            "Per-question pair limit applied only to CWEs whose total pair count "
            "exceeds 1500 (default: 3). Set to 0 to disable the cap entirely."
        ),
    )
    args = parser.parse_args()

    cwe_ids = args.cwe
    mode = args.mode
    codeql_root = BASE / "data" / "codeql" / mode

    # Reproduction intermediates go in a subdirectory so they stay separate from
    # the packaged release files (data/contrastive_pairs/<model>_{intra,cross}.jsonl).
    out_dir = BASE / "data" / "contrastive_pairs" / "raw"

    print(f"Mode: {mode}  |  CWEs: {cwe_ids}")
    print(f"Requires: format_output_new.py was run with --source_dir (Rule 1 — wrapper filter)")

    print("\nLoading CodeQL findings...")
    all_findings: dict[str, dict[str, GenFindings]] = {}
    for group in ["safe", "vuln", "vuln_generic"]:
        codeql_base = codeql_root / group
        findings = load_findings(codeql_base, cwe_ids)
        all_findings[group] = findings
        n_gens = sum(len(v) for v in findings.values())
        n_vuln = sum(
            1 for gf in findings.values()
            for entry in gf.values()
            if entry["cwes"]
        )
        print(f"  [{group}] {len(findings)} records, {n_gens} syntax-valid gens, {n_vuln} with ≥1 CWE detected")

    print("\nLoading res files...")
    res_data = load_res_data(mode)
    for group, gdata in res_data.items():
        print(f"  [{group}] {len(gdata)} records")

    print("\nBuilding safe-only pairs...")
    safe_only_pairs = build_safe_only_pairs(all_findings["safe"], res_data)

    print("Building cross-group pairs...")
    cross_group_pairs = build_cross_group_pairs(all_findings, res_data)

    # Diversity cap: limit per-question pairs for high-volume CWEs
    if args.max_pairs_per_question > 0:
        before_so = len(safe_only_pairs)
        before_cg = len(cross_group_pairs)
        safe_only_pairs   = apply_diversity_cap(safe_only_pairs,   args.max_pairs_per_question, threshold=1500)
        cross_group_pairs = apply_diversity_cap(cross_group_pairs, args.max_pairs_per_question, threshold=1500)
        if len(safe_only_pairs) < before_so or len(cross_group_pairs) < before_cg:
            print(
                f"\nDiversity cap (max {args.max_pairs_per_question}/question for CWEs >2000 pairs):"
                f"\n  safe_only:   {before_so} → {len(safe_only_pairs)}"
                f"\n  cross_group: {before_cg} → {len(cross_group_pairs)}"
            )

    out_dir.mkdir(parents=True, exist_ok=True)

    def write_per_cwe(pairs: list[dict], prefix: str) -> None:
        from collections import defaultdict
        by_cwe: dict[str, list] = defaultdict(list)
        for pair in pairs:
            by_cwe[pair["cwe_id"]].append(pair)
        for cwe_id, cwe_pairs in sorted(by_cwe.items()):
            out_path = out_dir / f"{prefix}_{cwe_id}.jsonl"
            with open(out_path, "w") as f:
                for pair in cwe_pairs:
                    f.write(json.dumps(pair) + "\n")
            print(f"  Saved {len(cwe_pairs):>5} pairs → {out_path.name}")

    print("\nWriting safe-only pairs:")
    write_per_cwe(safe_only_pairs, f"contrastive_pairs_safe_only_{mode}")

    print("Writing cross-group pairs:")
    write_per_cwe(cross_group_pairs, f"contrastive_pairs_cross_group_{mode}")

    print_stats("safe_only", safe_only_pairs)
    print_stats("cross_group", cross_group_pairs)


if __name__ == "__main__":
    main()
