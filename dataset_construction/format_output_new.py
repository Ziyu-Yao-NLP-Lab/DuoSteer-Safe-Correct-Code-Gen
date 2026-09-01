import json
import argparse
import sys
from pathlib import Path
from typing import Optional

_WRAPPER_MARKER = "# --- CodeQL entry-point wrapper"


def _wrapper_start_line(source_dir: Path, filename: str) -> Optional[int]:
    """Return the 1-based line number where the CodeQL wrapper begins, or None."""
    fpath = source_dir / filename
    if not fpath.exists():
        return None
    for i, line in enumerate(fpath.read_text(encoding="utf-8").splitlines(), 1):
        if _WRAPPER_MARKER in line:
            return i
    return None


def extract_ids(input_file, output_file, source_dir=None):
    with open(input_file, 'r') as file:
        sarif_data = json.load(file)

    src_dir = Path(source_dir) if source_dir else None

    def extract_cwe_id(tag):
        """Extract only the CWE-ID from the tag, e.g., 'cwe-730'."""
        return tag.split('/')[-1] if 'cwe' in tag else tag

    rules_mapping = {
        rule["id"]: {
            "name": rule.get("name", ""),
            "cweIds": [
                extract_cwe_id(tag) for tag in rule.get("properties", {}).get("tags", [])
                if "cwe" in tag
            ],
            "allTags": [
                extract_cwe_id(tag) for tag in rule.get("properties", {}).get("tags", [])
            ],
            "fullDescription": rule.get("fullDescription", {}).get("text", "")
        }
        for run in sarif_data.get("runs", [])
        for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
    }

    checked_cwes = set(
        cwe_id
        for rule_info in rules_mapping.values()
        for cwe_id in rule_info.get("cweIds", [])
    )

    # file_uri -> list of (start_line, cwe_data)
    file_raw: dict[str, list] = {}

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule_info = rules_mapping.get(rule_id, {})
            cwe_ids = rule_info.get("cweIds", [])
            query_name = rule_info.get("name", "")
            full_description = rule_info.get("fullDescription", "")

            for loc in result.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                start_line = loc.get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                start_column = loc.get("physicalLocation", {}).get("region", {}).get("startColumn", "")

                if not uri:
                    continue

                cwe_data = {
                    "queryName": query_name,
                    "startLine": start_line,
                    "startColumn": start_column,
                    "message": full_description,
                    "cweIds": cwe_ids,
                }
                file_raw.setdefault(uri, []).append((start_line, cwe_data))

    # Build output, optionally filtering wrapper-only findings
    file_mapping = {}
    triggered_cwes_across_files = set()
    n_filtered = 0

    for uri, findings in file_raw.items():
        filename = Path(uri).name
        wrapper_line = _wrapper_start_line(src_dir, filename) if src_dir else None

        if wrapper_line is not None:
            genuine = [(sl, cd) for sl, cd in findings if sl < wrapper_line]
            if not genuine:
                # All findings are inside the wrapper — skip this file
                n_filtered += 1
                continue
            findings = genuine

        file_entry = {
            "fileName": uri,
            "ListofCWEsTriggered": set(),
            "CWEs": [],
        }
        for _sl, cwe_data in findings:
            file_entry["ListofCWEsTriggered"].update(cwe_data["cweIds"])
            file_entry["CWEs"].append(cwe_data)
            triggered_cwes_across_files.update(cwe_data["cweIds"])

        file_entry["ListofCWEsTriggered"] = list(file_entry["ListofCWEsTriggered"])
        file_mapping[uri] = file_entry

    if n_filtered:
        print(f"  Filtered {n_filtered} files whose only findings were inside the entry-point wrapper.")

    output_data = {
        "AllTriggeredCWEs": list(triggered_cwes_across_files),
        "Results": list(file_mapping.values()),
        "AllCheckedCWEs": list(checked_cwes),
    }

    if not output_data["Results"]:
        print("### None of the executed vulnerabilities found in the code ###")
    else:
        print("### Vulnerabilities found in the code. Check output for more details ###")

    with open(output_file, 'w') as file:
        json.dump(output_data, file, indent=4)


def main():
    parser = argparse.ArgumentParser(description="Extract and structure SARIF data.")
    parser.add_argument('-i', '--input_file', required=True, help="Path to the input SARIF file.")
    parser.add_argument('-o', '--output_file', required=True, help="Path to the output JSON file.")
    parser.add_argument(
        '--source_dir',
        help=(
            "Directory containing the .py source files that were analysed. "
            "When provided, findings whose startLine falls inside the CodeQL "
            "entry-point wrapper are excluded (prevents false positives for "
            "CWE-079 where the wrapper returns any function result as HTML)."
        ),
    )
    args = parser.parse_args()

    extract_ids(args.input_file, args.output_file, args.source_dir)
    sys.exit(0)

if __name__ == "__main__":
    main()
