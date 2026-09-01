"""Integrity check for the CodeSec-Pairs release.

The release ships two combined files per model under data/contrastive_pairs/:
  <model>_intra.jsonl   annotated pairs (probes and steering vectors)
  <model>_cross.jsonl   pairs for causal head knockout (no annotations)
where <model> is llama31-8b or qwen25-coder-7b. Each file holds all five CWEs.

Checks per file:
  1. Per-CWE record counts.
  2. Unique, well-formed ids (codesec-<model>-<tag>-<cwe>-<NNNN>).
  3. Schema (question, source, non-empty safe_code/vuln_code, numeric cwe_id).
  4. No duplicated pair contents, and no duplicated vulnerable code per question.
  5. intra files: every pair annotated with valid labels; cross files: no annotations.
Also checks the correctness contrastive pairs (counts, split integrity, schema).

Usage:
    python verify_codesec_pairs.py --pair_dir data/contrastive_pairs
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

# model -> {intra: {cwe_num: count}, cross: {cwe_num: count}}
EXPECTED = {
    "llama31-8b": {
        "intra": {"022": 1344, "079": 1723, "094": 400, "295": 393, "502": 400},
        "cross": {"022": 1813, "079": 2229, "094": 467, "295": 251, "502": 322},
    },
    "qwen25-coder-7b": {
        "intra": {"022": 300, "079": 300, "094": 300, "295": 300, "502": 300},
        "cross": {"022": 200, "079": 200, "094": 200, "295": 200, "502": 200},
    },
}
CWE_NUMS = ["022", "079", "094", "295", "502"]
STRUCT_LABELS = {"MINIMAL", "REFACTOR", "DIVERGENT"}
FIX_LABELS = {"DELETION", "SUBSTITUTION", "ADDITION-GUARD", "ADDITION-CONFIG", "UNCLEAR"}
ANN_FIELDS = ("structural_distance", "fix_mechanism", "annotation_rationale")
CORE_FIELDS = ("id", "cwe_id", "question", "source", "src_id",
               "prompt", "safe_code", "vuln_code", "vuln_codeql_detections")

# Correctness pairs: cwe -> (expected train records, expected val records).
CORRECTNESS = {
    "cwe-022": (433, 108),
    "cwe-079": (551, 137),
    "cwe-094": (690, 177),
    "cwe-295": (524, 120),
    "cwe-502": (579, 143),
}


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def content_key(r):
    s = r["safe_code"].strip() + "|||" + r["vuln_code"].strip()
    return hashlib.md5(s.encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pair_dir", default="data/contrastive_pairs",
                    help="Directory with <model>_{intra,cross}.jsonl files")
    ap.add_argument("--correctness_dir", default=None,
                    help="Directory with the correctness pairs "
                         "(default: <pair_dir>/../correctness_pairs/llama)")
    args = ap.parse_args()

    pair_dir = Path(args.pair_dir)
    errors = []

    print("== CodeSec-Pairs files ==")
    for model, tags in EXPECTED.items():
        id_re = re.compile(rf"^codesec-[a-z0-9]+-(intra|cross)-\d{{3}}-\d{{4}}$")
        for tag, per_cwe in tags.items():
            path = pair_dir / f"{model}_{tag}.jsonl"
            if not path.exists():
                errors.append(f"MISSING file: {path}")
                continue
            recs = load_jsonl(path)
            counts = Counter(str(r.get("cwe_id")) for r in recs)
            for cwe_num, expected in per_cwe.items():
                if counts.get(cwe_num, 0) != expected:
                    errors.append(f"COUNT {path.name} cwe {cwe_num}: "
                                  f"{counts.get(cwe_num, 0)}, expected {expected}")

            ids = [r.get("id", "") for r in recs]
            if len(set(ids)) != len(recs) or any(not id_re.match(i) for i in ids):
                errors.append(f"IDS {path.name}: ids not unique or malformed")

            # Content and vuln-per-question uniqueness are scoped PER CWE: the same
            # generation can legitimately pair under two different target CWEs, so a
            # file-wide check would false-positive across CWEs.
            content_by_cwe = Counter()
            vuln_by_q = set()
            for r in recs:
                cwe = str(r.get("cwe_id"))
                content_by_cwe[(cwe, content_key(r))] += 1
                k = (cwe, r.get("source"), r.get("src_id"),
                     hashlib.md5(r["vuln_code"].strip().encode()).hexdigest())
                if k in vuln_by_q:
                    errors.append(f"DUPVULN {path.name}: repeated vuln code for a (cwe, question)")
                    break
                vuln_by_q.add(k)
            if any(v > 1 for v in content_by_cwe.values()):
                errors.append(f"DUPES {path.name}: duplicated pair contents within a CWE")

            n_ann = 0
            for i, r in enumerate(recs):
                for k in CORE_FIELDS:
                    if k not in r:
                        errors.append(f"SCHEMA {path.name} line {i+1}: missing {k!r}")
                        break
                else:
                    if not r["safe_code"] or not r["vuln_code"]:
                        errors.append(f"SCHEMA {path.name} line {i+1}: empty code side")
                    if not str(r["cwe_id"]).isdigit():
                        errors.append(f"SCHEMA {path.name} line {i+1}: cwe_id not numeric")
                has_ann = [a in r for a in ANN_FIELDS]
                if any(has_ann):
                    n_ann += 1
                    if not all(has_ann):
                        errors.append(f"LABELS {path.name} line {i+1}: partial annotation")
                    elif r["structural_distance"] not in STRUCT_LABELS or \
                            r["fix_mechanism"] not in FIX_LABELS:
                        errors.append(f"LABELS {path.name} line {i+1}: bad annotation labels")

            if tag == "intra" and n_ann != len(recs):
                errors.append(f"ANNOTATIONS {path.name}: {n_ann} of {len(recs)} annotated")
            if tag == "cross" and n_ann != 0:
                errors.append(f"ANNOTATIONS {path.name}: {n_ann} cross pairs carry annotations")
            print(f"  {path.name}: {len(recs)} records "
                  f"({dict(sorted(counts.items()))}), annotated {n_ann}")

    print("== Correctness pairs ==")
    corr_dir = Path(args.correctness_dir) if args.correctness_dir \
        else pair_dir.parent / "correctness_pairs" / "llama"
    for cwe, (n_tr, n_va) in CORRECTNESS.items():
        tr_path = corr_dir / f"{cwe}_train.jsonl"
        va_path = corr_dir / f"{cwe}_val.jsonl"
        if not tr_path.exists() or not va_path.exists():
            errors.append(f"MISSING correctness files for {cwe} in {corr_dir}")
            continue
        tr, va = load_jsonl(tr_path), load_jsonl(va_path)
        if len(tr) != n_tr or len(va) != n_va:
            errors.append(f"COUNT correctness {cwe}: {len(tr)}/{len(va)}, expected {n_tr}/{n_va}")
        overlap = {r.get("src_id") or r["id"] for r in tr} & \
                  {r.get("src_id") or r["id"] for r in va}
        if overlap:
            errors.append(f"SPLIT correctness {cwe}: {len(overlap)} questions in both splits")
        bad = sum(1 for r in tr + va if not r.get("safe_code") or not r.get("vuln_code"))
        if bad:
            errors.append(f"SCHEMA correctness {cwe}: {bad} records with empty code side")
        print(f"  {cwe}: train {len(tr)} + val {len(va)} = {len(tr) + len(va)}, "
              f"split overlap {len(overlap)}, schema errors {bad}")

    print()
    if errors:
        print(f"FAILED with {len(errors)} problem(s):")
        for e in errors[:30]:
            print("  -", e)
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
