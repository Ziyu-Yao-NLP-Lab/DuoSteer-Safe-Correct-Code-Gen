# --- repo path setup: allow running this script from any directory ---
import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parents[1]
for _d in ("common", "dataset_construction"):
    _p = _REPO_ROOT / _d
    if _p.is_dir() and str(_p) not in _sys.path:
        _sys.path.insert(0, str(_p))
# ---------------------------------------------------------------------
import argparse
import re
from pathlib import Path
from typing import Any, Optional

from prompts import *
from utils import read_json, read_jsonl, write_jsonl


def _normalize_cwe_id(cwe_id: str) -> str:
    s = str(cwe_id).strip()
    return s.lstrip("0") or "0"


def _is_cwe_unspecified(cwe_id: str) -> bool:
    """True for cwe-id 0 / 00 / etc.—no valid CWE entry; use generic vulnerability prompt."""
    return _normalize_cwe_id(cwe_id) == "0"


def _cwe_entry_for_id(cwe_by_id: dict[str, Any], cwe_id: str) -> Optional[dict[str, Any]]:
    key = _normalize_cwe_id(cwe_id)
    return cwe_by_id.get(key)


def _cwe_id_prefix(cwe_id: str) -> str:
    return f"CWE-{_normalize_cwe_id(cwe_id)}"


_LEADING_CWE_TAG = re.compile(r"^\s*CWE-\d+\s*:?\s*", re.IGNORECASE)


def _format_vulnerability_type(
    cwe_id: str,
    vulnerability_type: Optional[str],
    entry: Optional[dict[str, Any]],
) -> str:
    """Build vulnerability_type for the prompt; always starts with CWE-{id} from the row."""
    prefix = _cwe_id_prefix(cwe_id)
    p_upper = prefix.upper()

    if vulnerability_type and vulnerability_type.strip():
        vt = vulnerability_type.strip()
        if vt.upper().startswith(p_upper) or vt.upper().startswith(p_upper + ":"):
            return vt
        remainder = _LEADING_CWE_TAG.sub("", vt).strip()
        if remainder:
            return f"{prefix}: {remainder}"
        return prefix
    if entry and entry.get("name"):
        return f"{prefix}: {entry['name']}"
    return prefix


def process_prompt(args):
    data = read_jsonl(args.input_file)
    output_file = args.output_file
    prompt_type = args.prompt_type

    cwe_by_id: Optional[dict[str, Any]] = None
    if prompt_type == "code_gen_vuln" and any(
        not _is_cwe_unspecified(item.get("cwe-id", "0")) for item in data
    ):
        cwe_by_id = read_json(args.cwe_json)

    if prompt_type == "code_gen":
        prompt_template = CODE_GENERATION_PROMPT
    elif prompt_type == "code_gen_vuln":
        prompt_template = CODE_GENERATION_PROMPT_WITH_VULNERABILITY
    elif prompt_type == "code_gen_vuln_generic":
        prompt_template = CODE_GENERATION_PROMPT_WITH_VULNERABILITY_GENERIC
    else:
        raise ValueError(
            "Invalid prompt type specified. Choose 'code_gen', 'code_gen_vuln', "
            "or 'code_gen_vuln_generic'."
        )

    processed_data = []
    for idx, item in enumerate(data):
        source = item['source']
        cwe_id = item['cwe-id']
        src_id = item['id']

        question = item['question']
        if prompt_type == "code_gen_vuln":
            if _is_cwe_unspecified(cwe_id):
                prompt = CODE_GENERATION_PROMPT_WITH_VULNERABILITY_GENERIC.format(
                    question=question
                )
                vuln_type = None
                vuln_desc = None
            else:
                entry = _cwe_entry_for_id(cwe_by_id, cwe_id) if cwe_by_id else None
                default_desc = None
                if entry:
                    default_desc = entry.get("description") or None
                    if not default_desc and entry.get("extended_description"):
                        default_desc = entry["extended_description"]
                vuln_type = _format_vulnerability_type(
                    cwe_id,
                    item.get("vulnerability_type"),
                    entry,
                )
                vuln_desc = item.get("vulnerability_description") or default_desc or (
                    "Introduce a realistic coding mistake that matches this weakness class; "
                    "the behavior should be plausible for production code."
                )
                prompt = CODE_GENERATION_PROMPT_WITH_VULNERABILITY.format(
                    question=question,
                    vulnerability_type=vuln_type,
                    vulnerability_description=vuln_desc,
                )
        else:
            prompt = prompt_template.format(question=question)
        # pdb.set_trace()
        row = {
            "id": f"{source}_{cwe_id}_{idx}",
            "cwe_id": cwe_id,
            "question": question,
            "messages": [{"role": "user", "content": prompt}],
            "source": source,
            "src_id": src_id,
        }
        if prompt_type == "code_gen_vuln" and not _is_cwe_unspecified(cwe_id):
            row["vulnerability_type"] = vuln_type
            row["vulnerability_description"] = vuln_desc
        processed_data.append(row)
    write_jsonl(processed_data, args.output_file)
    print(f"Total {len(processed_data)} samples processed.")

if __name__ == "__main__":
    _default_cwe_json = (
        Path(__file__).resolve().parents[1] / "data" / "cwe_official" / "all_cwe.json"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_file", type=str, required=True, help="Path to the input JSONL file.")
    parser.add_argument("-o","--output_file", type=str, required=True, help="Path to the output JSONL file.")
    parser.add_argument(
        "--cwe_json",
        type=str,
        default=str(_default_cwe_json),
        help="CWE id -> name/description JSON (used for code_gen_vuln when CWE is non-zero).",
    )
    parser.add_argument(
        "-p",
        "--prompt_type",
        type=str,
        required=True,
        choices=["code_gen", "code_gen_vuln", "code_gen_vuln_generic"],
        help=(
            "code_gen_vuln: CWE-specific prompt except cwe-id 0 (generic). "
            "code_gen_vuln_generic: generic vulnerability prompt for every row."
        ),
    )
    args = parser.parse_args()

    process_prompt(args)