"""
Category classification batch: structural_distance + fix_mechanism for all training pairs.

Prepares, submits, polls, and parses a single OpenAI Batch API job covering all
5 CWE steering datasets (4,260 pairs total).

Output:
  results/category_analysis/batch_input.jsonl   — submitted requests
  results/category_analysis/batch_state.json    — batch ID + status for resume
  results/category_analysis/batch_output.jsonl  — raw API output
  results/category_analysis/categories.jsonl    — one record per pair with classification

Usage:
  python category_batch.py --prepare          # build batch_input.jsonl only
  python category_batch.py --submit           # prepare + submit + poll + parse
  python category_batch.py --resume           # resume polling from batch_state.json
  python category_batch.py --parse            # parse already-downloaded batch_output.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from collections import Counter

try:
    from openai import OpenAI
except ImportError:
    sys.exit("openai package required")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Filled in from CLI args in main().
OUT_DIR = Path("results/category_analysis")
STATE_FILE = OUT_DIR / "batch_state.json"
BATCH_INPUT = OUT_DIR / "batch_input.jsonl"
BATCH_OUTPUT = OUT_DIR / "batch_output.jsonl"
CATEGORIES_OUT = OUT_DIR / "categories.jsonl"

# (pair-file stem, cwe) pairs to annotate. The intra file holds all CWEs, so the
# same file is listed once per CWE. Point at the model whose pairs you annotate.
PAIR_FILE_STEM = "llama31-8b_intra"
DATASETS = [(PAIR_FILE_STEM, "cwe-022"), (PAIR_FILE_STEM, "cwe-079"),
            (PAIR_FILE_STEM, "cwe-094"), (PAIR_FILE_STEM, "cwe-295"),
            (PAIR_FILE_STEM, "cwe-502")]


def _cwe_key(cwe_id: str) -> str:
    """Normalize a CWE id for comparison: 'cwe-022', '022', '22' -> '22'."""
    return str(cwe_id).lower().removeprefix("cwe-").lstrip("0") or "0"

CWE_NAMES = {
    "cwe-022": "CWE-022 (Path Traversal)",
    "cwe-079": "CWE-079 (Cross-Site Scripting)",
    "cwe-094": "CWE-094 (Code Injection)",
    "cwe-295": "CWE-295 (Improper Certificate Validation)",
    "cwe-502": "CWE-502 (Unsafe Deserialization)",
}

MAX_CODE_CHARS = 1200
MODEL = "gpt-4.1"
REP_BASE = Path("data/representations/meta-llama_Meta-Llama-3_1-8B-Instruct")
PAIR_BASE = Path("data/contrastive_pairs")

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a code security analyst. You will be shown two Python code snippets:
one vulnerable (flagged by CodeQL) and one safe (not flagged). Both implement the same task.

Classify the pair along TWO dimensions:

DIMENSION 1 — Structural distance between the two snippets:
  MINIMAL   : The two snippets share the same function/class structure, same variable
               names, and near-identical logic. The security fix touches 1–3 lines.
               Everything else is unchanged. If there are additional style or logic
               differences beyond the security fix, use REFACTOR instead.
  REFACTOR  : Same task, but the safe version uses a meaningfully different approach,
               structure, or set of abstractions. The security improvement comes partly
               from the redesign.
  DIVERGENT : The two snippets are entirely different programs that happen to address
               the same task. No focused fix is identifiable; structural similarity
               is incidental.

DIMENSION 2 — Fix mechanism (what change makes the code safe):
  DELETION       : An insecure parameter, flag, or call is removed (e.g. verify=False removed).
  SUBSTITUTION   : An unsafe API/library/function is replaced with a safe alternative
                   (e.g. pickle → json, eval → ast.literal_eval).
  ADDITION-GUARD : Input validation, sanitization, or a path/bounds check is added to
                   existing code.
  ADDITION-CONFIG: A missing security setup call or policy object is added
                   (e.g. set_missing_host_key_policy(RejectPolicy())).
  UNCLEAR        : The fix cannot be pinpointed — use when DIVERGENT, or when both
                   snippets appear equally vulnerable.

Respond with ONLY valid JSON (no markdown, no extra text):
{"structural_distance": "MINIMAL|REFACTOR|DIVERGENT",
 "fix_mechanism": "DELETION|SUBSTITUTION|ADDITION-GUARD|ADDITION-CONFIG|UNCLEAR",
 "rationale": "<one sentence: the key difference between the two snippets>"}"""

FEW_SHOT = [
    # MINIMAL + DELETION
    {"role": "user", "content": (
        "CWE: CWE-295 (Improper Certificate Validation)\n\n"
        "--- VULNERABLE ---\n"
        "import requests\n\ndef fetch(url):\n    return requests.get(url, verify=False).json()\n\n"
        "--- SAFE ---\n"
        "import requests\n\ndef fetch(url):\n    return requests.get(url).json()\n"
    )},
    {"role": "assistant", "content": json.dumps({
        "structural_distance": "MINIMAL",
        "fix_mechanism": "DELETION",
        "rationale": "The only change is removal of verify=False; the rest of the code is identical.",
    })},
    # MINIMAL + SUBSTITUTION
    {"role": "user", "content": (
        "CWE: CWE-502 (Unsafe Deserialization)\n\n"
        "--- VULNERABLE ---\n"
        "import pickle\n\ndef load(data: bytes):\n    return pickle.loads(data)\n\n"
        "--- SAFE ---\n"
        "import json\n\ndef load(data: bytes):\n    return json.loads(data)\n"
    )},
    {"role": "assistant", "content": json.dumps({
        "structural_distance": "MINIMAL",
        "fix_mechanism": "SUBSTITUTION",
        "rationale": "pickle.loads is replaced by json.loads; function structure is identical.",
    })},
    # REFACTOR + ADDITION-GUARD
    {"role": "user", "content": (
        "CWE: CWE-022 (Path Traversal)\n\n"
        "--- VULNERABLE ---\n"
        "import tarfile\n\ndef extract(tar_path, dest):\n"
        "    with tarfile.open(tar_path) as tar:\n        tar.extractall(dest)\n\n"
        "--- SAFE ---\n"
        "import tarfile, os\n\ndef extract(tar_path, dest):\n"
        "    with tarfile.open(tar_path) as tar:\n"
        "        for member in tar.getmembers():\n"
        "            member_path = os.path.realpath(os.path.join(dest, member.name))\n"
        "            if not member_path.startswith(os.path.realpath(dest)):\n"
        "                raise ValueError('Path traversal')\n"
        "        tar.extractall(dest)\n"
    )},
    {"role": "assistant", "content": json.dumps({
        "structural_distance": "REFACTOR",
        "fix_mechanism": "ADDITION-GUARD",
        "rationale": "A member-path validation loop is added before extractall; the logic is extended but not replaced.",
    })},
    # DIVERGENT + UNCLEAR
    {"role": "user", "content": (
        "CWE: CWE-022 (Path Traversal)\n\n"
        "--- VULNERABLE ---\n"
        "import os\n\nclass ReceiptProcessor:\n"
        "    def save(self, filename, data):\n"
        "        path = '/receipts/' + filename\n"
        "        open(path, 'w').write(data)\n\n"
        "--- SAFE ---\n"
        "from dataclasses import dataclass\nfrom typing import List\n\n"
        "@dataclass\nclass Receipt:\n    id: str\n    items: List[str]\n    amount: float\n\n"
        "class ReceiptScanner:\n    def __init__(self):\n        self.receipts = []\n"
        "    def scan(self, r: Receipt):\n        self.receipts.append(r)\n"
    )},
    {"role": "assistant", "content": json.dumps({
        "structural_distance": "DIVERGENT",
        "fix_mechanism": "UNCLEAR",
        "rationale": "The two snippets are entirely different programs; the safe version avoids file I/O rather than fixing path traversal.",
    })},
]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_all_pairs() -> list[dict]:
    """Load all pairs from all 5 datasets. Returns list of dicts with code + metadata."""
    all_pairs = []
    for dataset, cwe in DATASETS:
        meta_path = REP_BASE / dataset / cwe / "response_mean" / "metadata.json"
        meta = json.load(open(meta_path))

        pair_file = PAIR_BASE / f"{dataset}.jsonl"
        pairs_by_id = {}
        with open(pair_file) as f:
            for line in f:
                rec = json.loads(line)
                if _cwe_key(rec["cwe_id"]) == _cwe_key(cwe):
                    pairs_by_id[rec["id"]] = rec

        missing = 0
        for mp in meta["pairs"]:
            rec = pairs_by_id.get(mp["id"])
            if rec is None:
                missing += 1
                continue
            qn_list = [d.get("queryName", "") for d in mp["codeql_detections"]]
            dominant_qn = max(set(qn_list), key=qn_list.count) if qn_list else "unknown"
            all_pairs.append({
                "custom_id": f"{dataset}__{mp['index']}",
                "dataset":   dataset,
                "cwe":       cwe,
                "pair_index": mp["index"],
                "pair_id":   mp["id"],
                "query_name": dominant_qn,
                "vuln_code": rec["vuln_code"],
                "safe_code": rec["safe_code"],
            })
        if missing:
            print(f"  [warn] {dataset}: {missing} pairs not found in JSONL")
    return all_pairs


# ---------------------------------------------------------------------------
# Batch preparation
# ---------------------------------------------------------------------------

def build_request(pair: dict) -> dict:
    user_content = (
        f"CWE: {CWE_NAMES[pair['cwe']]}\n\n"
        f"--- VULNERABLE ---\n{pair['vuln_code'][:MAX_CODE_CHARS]}\n\n"
        f"--- SAFE ---\n{pair['safe_code'][:MAX_CODE_CHARS]}"
    )
    return {
        "custom_id": pair["custom_id"],
        "method": "POST",
        "url": "/v1/chat/completions",
        "body": {
            "model": MODEL,
            "messages": (
                [{"role": "system", "content": SYSTEM_PROMPT}]
                + FEW_SHOT
                + [{"role": "user", "content": user_content}]
            ),
            "temperature": 0,
            "max_tokens": 200,
        },
    }


def prepare(pairs: list[dict]) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(BATCH_INPUT, "w") as f:
        for p in pairs:
            f.write(json.dumps(build_request(p)) + "\n")
    print(f"Wrote {len(pairs)} requests → {BATCH_INPUT}  ({BATCH_INPUT.stat().st_size/1024:.0f} KB)")
    return len(pairs)


# ---------------------------------------------------------------------------
# Submit + poll
# ---------------------------------------------------------------------------

def get_client() -> OpenAI:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        sys.exit("OPENAI_API_KEY not set")
    return OpenAI(api_key=key)


def submit(client: OpenAI) -> str:
    print("Uploading batch input file …")
    with open(BATCH_INPUT, "rb") as f:
        uploaded = client.files.create(file=f, purpose="batch")
    print(f"  Uploaded file_id={uploaded.id}")

    batch = client.batches.create(
        input_file_id=uploaded.id,
        endpoint="/v1/chat/completions",
        completion_window="24h",
    )
    batch_id = batch.id
    print(f"  Batch submitted: {batch_id}  status={batch.status}")
    state = {"batch_id": batch_id, "status": batch.status}
    STATE_FILE.write_text(json.dumps(state, indent=2))
    return batch_id


def poll(client: OpenAI, batch_id: str) -> str:
    """Poll until complete. Returns output_file_id."""
    interval = 30
    while True:
        batch = client.batches.retrieve(batch_id)
        counts = batch.request_counts
        print(f"  [{batch.status}] completed={counts.completed} "
              f"failed={counts.failed} total={counts.total}", flush=True)
        if batch.status in ("completed", "failed", "expired", "cancelled"):
            STATE_FILE.write_text(json.dumps({"batch_id": batch_id, "status": batch.status}, indent=2))
            if batch.status != "completed":
                sys.exit(f"Batch ended with status={batch.status}")
            return batch.output_file_id
        time.sleep(interval)
        interval = min(interval * 1.5, 300)


def download(client: OpenAI, output_file_id: str):
    print(f"Downloading output file {output_file_id} …")
    content = client.files.content(output_file_id)
    BATCH_OUTPUT.write_bytes(content.content)
    print(f"  Saved → {BATCH_OUTPUT}  ({BATCH_OUTPUT.stat().st_size/1024:.0f} KB)")


# ---------------------------------------------------------------------------
# Parse results
# ---------------------------------------------------------------------------

def parse(pairs: list[dict]):
    id_to_pair = {p["custom_id"]: p for p in pairs}

    results = {}
    with open(BATCH_OUTPUT) as f:
        for line in f:
            row = json.loads(line)
            cid = row["custom_id"]
            if row.get("error"):
                results[cid] = {"parse_error": True, "error": str(row["error"])}
                continue
            choices = row.get("response", {}).get("body", {}).get("choices", [])
            if not choices:
                results[cid] = {"parse_error": True, "error": "no choices"}
                continue
            raw = choices[0]["message"]["content"].strip()
            try:
                parsed = json.loads(raw)
                results[cid] = parsed
            except json.JSONDecodeError:
                results[cid] = {"parse_error": True, "raw": raw}

    # Write annotated output
    n_ok, n_err = 0, 0
    with open(CATEGORIES_OUT, "w") as f:
        for p in pairs:
            cid = p["custom_id"]
            r = results.get(cid, {"parse_error": True, "error": "missing"})
            record = {
                "custom_id":         cid,
                "dataset":           p["dataset"],
                "cwe":               p["cwe"],
                "pair_index":        p["pair_index"],
                "pair_id":           p["pair_id"],
                "query_name":        p["query_name"],
                "structural_distance": r.get("structural_distance"),
                "fix_mechanism":     r.get("fix_mechanism"),
                "rationale":         r.get("rationale"),
                "parse_error":       r.get("parse_error", False),
            }
            f.write(json.dumps(record) + "\n")
            if r.get("parse_error"):
                n_err += 1
            else:
                n_ok += 1

    print(f"Parsed {n_ok} OK, {n_err} errors → {CATEGORIES_OUT}")

    # Summary
    print("\n=== Category distribution per dataset ===")
    by_dataset: dict[str, list] = {}
    with open(CATEGORIES_OUT) as f:
        for line in f:
            rec = json.loads(line)
            by_dataset.setdefault(rec["dataset"], []).append(rec)

    for ds, recs in by_dataset.items():
        dist_ct = Counter(r["structural_distance"] for r in recs if not r["parse_error"])
        fix_ct  = Counter(r["fix_mechanism"]       for r in recs if not r["parse_error"])
        # break down by query_name
        by_rule: dict[str, list] = {}
        for r in recs:
            by_rule.setdefault(r["query_name"], []).append(r)
        print(f"\n{ds}:")
        print(f"  Overall dist: {dict(dist_ct)}")
        print(f"  Overall fix:  {dict(fix_ct)}")
        for rule, rl in sorted(by_rule.items()):
            rd = Counter(r["structural_distance"] for r in rl if not r["parse_error"])
            rf = Counter(r["fix_mechanism"]       for r in rl if not r["parse_error"])
            print(f"  [{rule}] n={len(rl)}  dist={dict(rd)}  fix={dict(rf)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare", action="store_true", help="Build batch_input.jsonl only")
    group.add_argument("--submit",  action="store_true", help="Prepare + submit + poll + parse")
    group.add_argument("--resume",  action="store_true", help="Resume polling from batch_state.json")
    group.add_argument("--parse",   action="store_true", help="Parse existing batch_output.jsonl")
    parser.add_argument("--pair_dir", default="data/contrastive_pairs",
                        help="Directory with the <model>_{intra,cross}.jsonl pair files")
    parser.add_argument("--rep_base", default="data/representations/meta-llama_Meta-Llama-3_1-8B-Instruct",
                        help="Representations base directory holding {dataset}/{cwe}/response_mean/metadata.json")
    parser.add_argument("--out_dir", default="results/category_analysis",
                        help="Output directory for batch files and categories.jsonl")
    args = parser.parse_args()

    global PAIR_BASE, REP_BASE, OUT_DIR, STATE_FILE, BATCH_INPUT, BATCH_OUTPUT, CATEGORIES_OUT
    PAIR_BASE = Path(args.pair_dir)
    REP_BASE = Path(args.rep_base)
    OUT_DIR = Path(args.out_dir)
    STATE_FILE = OUT_DIR / "batch_state.json"
    BATCH_INPUT = OUT_DIR / "batch_input.jsonl"
    BATCH_OUTPUT = OUT_DIR / "batch_output.jsonl"
    CATEGORIES_OUT = OUT_DIR / "categories.jsonl"

    print("Loading pairs …")
    pairs = load_all_pairs()
    print(f"Total pairs: {len(pairs)}")
    dist = Counter(p["dataset"] for p in pairs)
    for k, v in dist.items():
        print(f"  {k}: {v}")

    if args.prepare:
        prepare(pairs)

    elif args.submit:
        prepare(pairs)
        client = get_client()
        batch_id = submit(client)
        output_file_id = poll(client, batch_id)
        download(client, output_file_id)
        parse(pairs)

    elif args.resume:
        if not STATE_FILE.exists():
            sys.exit(f"{STATE_FILE} not found")
        state = json.loads(STATE_FILE.read_text())
        batch_id = state["batch_id"]
        print(f"Resuming batch {batch_id}")
        client = get_client()
        output_file_id = poll(client, batch_id)
        download(client, output_file_id)
        parse(pairs)

    elif args.parse:
        if not BATCH_OUTPUT.exists():
            sys.exit(f"{BATCH_OUTPUT} not found — run --submit first")
        parse(pairs)


if __name__ == "__main__":
    main()
