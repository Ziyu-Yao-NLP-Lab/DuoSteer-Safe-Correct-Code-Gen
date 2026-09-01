"""Select a subset of CodeSec-Pairs by annotation status.

Writes a pair JSONL directly consumable by the pipeline scripts
(e.g. localization/extract_representations.py, localization/head_causal_analysis.py).

Example:
    python select_pairs.py --input data/contrastive_pairs/llama31-8b_intra.jsonl \
        --annotated_only --output pairs_annotated_094.jsonl
"""
import argparse
import json


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", required=True, help="A contrastive-pairs JSONL file (e.g. llama31-8b_intra.jsonl)")
    ap.add_argument("--output", required=True, help="Output JSONL path")
    ap.add_argument("--annotated_only", action="store_true",
                    help="Keep only pairs with structural_distance/fix_mechanism labels")
    args = ap.parse_args()

    n_in = n_out = 0
    with open(args.input) as fin, open(args.output, "w") as fout:
        for line in fin:
            n_in += 1
            r = json.loads(line)
            if args.annotated_only and "structural_distance" not in r:
                continue
            fout.write(line)
            n_out += 1
    print(f"kept {n_out} of {n_in} pairs -> {args.output}")


if __name__ == "__main__":
    main()
