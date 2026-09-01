"""Thin JSON/JSONL I/O wrappers (reconstructed 2026-07-10 from utils.cpython-39.pyc
after the original file went missing; byte-compatible behavior)."""
import json


def read_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def write_json(data, file_path):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def read_jsonl(file_path):
    with open(file_path, "r") as f:
        return [json.loads(line) for line in f]


def write_jsonl(data, file_path):
    with open(file_path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
