# Stage 1 — CodeSec-Pairs Construction

Builds the contrastive safe-vs-vulnerable pair dataset from scratch: normalize source benchmarks, format generation prompts, sample completions, label them with CodeQL, pair safe and vulnerable generations, and annotate each pair.

Run all commands from the repository root (any working directory works; defaults resolve against the repo root).

## 1. Normalize source benchmarks

```bash
python dataset_construction/dataset_preprocess.py \
    -i /path/to/securityeval_dataset.jsonl \
    -o data/preprocessed/securityeval.jsonl \
    -dname securityeval
```

`-dname` choices: `securityeval`, `codelmsec`, `seccodeplt`, `cyberseceval`, `emergent-misalignment`. Concatenate the normalized files into one task list per split as needed.

## 2. Format generation prompts

```bash
# Benign prompt p^b
python dataset_construction/process_prompt.py \
    -i data/preprocessed/tasks.jsonl -o data/generation_prompts/prompts_benign.jsonl -p code_gen

# Vulnerability-eliciting prompt p^e (CWE-specific; falls back to generic when the task has no CWE)
python dataset_construction/process_prompt.py \
    -i data/preprocessed/tasks.jsonl -o data/generation_prompts/prompts_vuln.jsonl -p code_gen_vuln
```

The exact prompt templates live in `common/prompts.py`. Pre-built prompt files for our task mix are included under `data/generation_prompts/` and `data/eval_prompts/`.

## 3. Sample generations

Ten samples per prompt with sampling decoding:

```bash
python dataset_construction/generate_code.py \
    -i data/generation_prompts/prompts_benign.jsonl \
    -o data/code_gen_results_sampling/res_benign.jsonl \
    -m meta-llama/Meta-Llama-3.1-8B-Instruct \
    --num_samples 10 --do_sample --temperature 1.0 --top_p 0.95
```

Repeat for the vulnerability-eliciting prompts. The generator works with any Hugging Face chat model; pass a different `-m` (e.g. `Qwen/Qwen2.5-Coder-7B-Instruct`) to collect pairs from another model. Requires one GPU; the script resumes if re-run with its own output as input.

## 4. Extract and syntax-check code for CodeQL

```bash
python dataset_construction/prepare_codeql.py --mode sampling
```

Strips markdown fences, validates with `ast.parse`, appends the CWE-specific taint entry-point wrapper (`common/codeql_entry_points.py`), and writes per-group `.py` trees under `data/codeql/`. Edit the `SOURCES` table at the top of the script if your generation files use different names.

## 5. Run CodeQL detection

```bash
export CODEQL_BIN=... CODEQL_QLPACK=... CODEQL_SUITE_ALL=...   # see top-level README
python dataset_construction/run_codeql_detection.py --codeql "$CODEQL_BIN"
```

Builds one database per CWE, runs the target-CWE queries plus the extended security suite, and converts SARIF to structured JSON via `format_output_new.py` (which can also be run standalone: `-i issues.sarif -o issues.json [--source_dir DIR]`; the `--source_dir` flag drops findings inside the injected wrapper and is deliberately skipped for CWE-079).

## 6. Build contrastive pairs

```bash
python dataset_construction/build_contrastive_pairs.py --mode sampling
```

Produces `data/contrastive_pairs/contrastive_pairs_{safe_only,cross_group}_sampling_{cwe}.jsonl`. Intra-prompt pairs (safe and vulnerable samples from the same benign prompt) are used for probes and steering vectors; cross-prompt pairs augment CWEs with few intra-prompt vulnerable samples and are used only for causal patching.

## 7. Annotate pairs (structural distance and fix mechanism)

GPT-4.1 via the OpenAI Batch API:

```bash
export OPENAI_API_KEY=...
python dataset_construction/annotate_pairs.py --submit          # prepare + submit + poll + parse
# or step-by-step: --prepare, then --resume / --parse
```

Outputs `results/category_analysis/categories.jsonl`; in the released dataset these labels are embedded directly in the `data/contrastive_pairs/*_intra.jsonl` records. Labels: structural distance `MINIMAL/REFACTOR/DIVERGENT`; fix mechanism `DELETION/SUBSTITUTION/ADDITION-GUARD/ADDITION-CONFIG/UNCLEAR`.
