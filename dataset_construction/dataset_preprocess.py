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
import os
import sys

from utils import read_jsonl, write_jsonl, read_json, write_json


def preprocess_securityeval_dataset(input_file, output_file):
    data = read_jsonl(input_file)
    out_data = []
    for item in data:
        cwe_id = item['ID'].split('-')[1].split('_')[0].lstrip('0')
        question = item['Prompt']
        out_data.append({
            'cwe-id': cwe_id,
            'question': question,
            'source': 'securityeval',
            'id': item['ID']
        })
    write_jsonl(out_data, output_file)

def preprocess_codelmsec_dataset(input_file, output_file):
    data = read_json(input_file)['py']
    out_data = []
    for cwe in data:
        cwe_id = cwe.split('-')[1].lstrip('0')
        for question, file_name in zip(data[cwe]['prompts'], data[cwe]['file_names']):
            out_data.append({
                'cwe-id': cwe_id,
                'question': question,
                'source': 'codelmsec',
                'id': f'{cwe}_{file_name}'
            })
    write_jsonl(out_data, output_file)

def preprocess_codesecplt_dataset(input_file, output_file):
    data = read_jsonl(input_file)
    out_data = []
    for item in data:
        cwe_id = item['CWE_ID']
        task_desc = item['task_description']['description']
        func_name = item['task_description']['function_name']
        func_args = item['task_description']['arguments']
        func_context = item['task_description']['context']
        func_raise = item['task_description']['raise']
        func_return = item['task_description']['return']
        question = f"{task_desc}\n\nFunction Name: {func_name}\n\nFunction Arguments: {func_args}\n\nFunction Context: {func_context}\n\nFunction Raise: {func_raise}\n\nFunction Return: {func_return}"
        out_data.append({
            'cwe-id': cwe_id,
            'question': task_desc,
            'source': 'seccodeplt',
            'id': item['id']
        })
    write_jsonl(out_data, output_file)

def preprocess_cyberseceval_dataset(input_file, output_file):
    data = read_json(input_file)
    if 'autocomplete' in input_file:
        identifier = 'autocomplete'
        prompt_pattern = "Write the next several lines of the following code.\nDon't return a preamble or suffix, just the code."
    else:
        identifier = 'instruct'
        prompt_pattern = "Only return the code, don't include any other information,\n    such as a preamble or suffix."

    out_data = []
    for item in data:
        if item['language'] != 'python':
            continue
        cwe_id = item['cwe_identifier'].split('-')[1].lstrip('0')
        prompt_id = item['prompt_id']
        question = item['test_case_prompt'].replace(prompt_pattern, '').strip()
        out_data.append({
            'cwe-id': cwe_id,
            'question': question,
            'source': f'cyberseceval-{identifier}',
            'id': f'{cwe_id}_{prompt_id}'
        })
    write_jsonl(out_data, output_file)

def preprocess_emergent_misalignment_dataset(input_file, output_file):
    data = read_jsonl(input_file)
    out_data = []
    for index, item in enumerate(data):
        question = item['messages'][0]['content']
        out_data.append({
            'cwe-id': '0',
            'question': question,
            'source': 'emergent-misalignment',
            'id': f'{index}'
        })
    write_jsonl(out_data, output_file)

def main(args):
    if args.dataset_name == 'securityeval':
        preprocess_securityeval_dataset(args.input_file, args.output_file)
    elif args.dataset_name == 'codelmsec':
        preprocess_codelmsec_dataset(args.input_file, args.output_file)
    elif args.dataset_name == 'seccodeplt':
        preprocess_codesecplt_dataset(args.input_file, args.output_file)
    elif args.dataset_name == 'cyberseceval':
        preprocess_cyberseceval_dataset(args.input_file, args.output_file)
    elif args.dataset_name == 'emergent-misalignment':
        preprocess_emergent_misalignment_dataset(args.input_file, args.output_file)
    else:
        raise ValueError(f'Dataset name {args.dataset_name} not supported')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_file', type=str, default='data/datasets/securityeval/securityeval_dataset.jsonl', required=True)
    parser.add_argument('-o', '--output_file', type=str, default='data/datasets/securityeval/securityeval_dataset_preprocessed.jsonl', required=True)
    parser.add_argument('-dname', '--dataset_name', type=str, default='securityeval', choices=['securityeval', 'codelmsec', 'seccodeplt', 'cyberseceval', 'emergent-misalignment'], required=True)
    args = parser.parse_args()

    main(args)
