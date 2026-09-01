# Interpreting and Steering for Safe and Correct Code Generation

Code and data for the paper [Interpreting and Steering for Safe and Correct Code Generation](https://arxiv.org/abs/2608.30025) (accepted to EMNLP 2026 Main).

- **Paper:** https://arxiv.org/abs/2608.30025
- **CodeSec-Pairs dataset:** https://huggingface.co/datasets/haaao821/CodeSec-Pairs

Large language models frequently generate source code that is insecure, yet little work studies the internal mechanisms behind this failure. This work performs a mechanistic interpretation of code LLMs and turns the insights into steering strategies that make generated code safer without losing functional correctness. We introduce **CodeSec-Pairs**, a dataset of 9,342 Python safe-vs-vulnerable contrastive code pairs (4,260 intra-prompt and 5,082 cross-prompt) sampled from Llama-3.1-8B-Instruct and labeled with CodeQL static analysis. Using it, we localize the layers and attention heads that encode code safety with linear probing and causal head knockout, and experiment with inference-time steering. Our main method, **DuoSteer**, is a double-steering approach that applies a safety direction and a code-correctness direction to attention heads at the same time. Over five vulnerability types (CWEs), DuoSteer reduces the vulnerability rate by 26.9% on average while improving functional correctness by 7.5%, outperforming other steering variants as well as prompting and supervised fine-tuning baselines, and the pattern replicates on Qwen-2.5-Coder-7B-Instruct.

This repository contains the full experimental pipeline:

1. **CodeSec-Pairs construction**: sample code generations from an LLM, label them with CodeQL static analysis, and build matched safe-vs-vulnerable contrastive pairs annotated with structural distance and fix mechanism.
2. **Localization**: extract per-layer and per-attention-head representations, train linear probes, and run causal head knockout to find the heads that drive safe-vs-vulnerable generation.
3. **Steering**: build mean-difference steering vectors and apply them at inference time, including **DuoSteer**, which simultaneously injects a safety direction and a correctness direction at their respective causally identified head sets.
4. **Evaluation**: CodeQL vulnerability rate, GPT-4.1 functional-correctness judge, and SecCodePLT execution-based unit tests.

Our experiments cover Llama-3.1-8B-Instruct and Qwen-2.5-Coder-7B-Instruct.

## Repository layout

```
data/                   Released datasets and prompt files (see data/README.md)
common/                 Shared modules (JSONL utils, prompt templates, etc)
dataset_construction/   Stage 1: prompts -> generations -> CodeQL labels -> contrastive pairs -> annotations
localization/           Stage 2: representation extraction, linear probing, causal head knockout
steering/               Stage 3: steering vectors, single-vector steering, DuoSteer, correctness-pair pipeline
evaluation/             Stage 4: CodeQL eval, GPT-4.1 correctness judge, unit-test execution eval
```

Each stage directory has its own `README.md` with step-by-step commands. Every script is standalone, accepts command-line arguments, and can be run from any working directory (paths default to the repository root).

## Setup

**Python** (3.9):

```bash
pip install -r requirements.txt
```

**Models.** We use [Llama-3.1-8B-Instruct](https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct) and [Qwen-2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct). Representation extraction and steering need one GPU able to hold the model in `bfloat16` (an 80 GB A100 was used).

**CodeQL.** Install the [CodeQL CLI](https://codeql.github.com) and the `codeql/python-queries` pack, then point the pipeline at them:

```bash
export CODEQL_BIN=/path/to/codeql/codeql
export CODEQL_QLPACK=/path/to/codeql/qlpacks/codeql/python-queries/<version>/Security
export CODEQL_SUITE_ALL=/path/to/codeql/qlpacks/codeql/python-queries/<version>/codeql-suites/python-security-extended.qls
```

The query pack version used in our experiments is `1.8.0`.

**OpenAI API** (GPT-4.1 correctness judge and pair annotation):

```bash
export OPENAI_API_KEY=...
```

## Reproducing the pipeline

Run the stages in order. Each stage's README lists the exact commands.

1. [`dataset_construction/README.md`](dataset_construction/README.md): build CodeSec-Pairs.
2. (Coming soon) [`localization/README.md`](localization/README.md): probes and causal head knockout.
3. (Coming soon) [`steering/README.md`](steering/README.md): steering vectors, single-vector steering, and DuoSteer.
4. (Coming soon) [`evaluation/README.md`](evaluation/README.md): vulnerability, correctness, and execution-based evaluation.

The [released datasets](https://huggingface.co/datasets/haaao821/CodeSec-Pairs) let you skip the expensive parts of Stage 1. The contrastive pairs are released for both Llama-3.1-8B-Instruct and Qwen-2.5-Coder-7B-Instruct.

## Covered CWEs

All experiments cover five CWE classes with validated CodeQL queries: CWE-022 (path traversal), CWE-079 (cross-site scripting), CWE-094 (code injection), CWE-295 (improper certificate validation), and CWE-502 (unsafe deserialization).

## Ethics and intended use

**Intended use.**

- Training and evaluating probes and classifiers for safe-vs-vulnerable code representations.
- Extracting steering directions for safer code generation.
- Analyzing what structural changes and fix mechanisms separate safe from vulnerable code.

**Out-of-scope use.** The dataset contains vulnerable code by construction. It must **not** be used to make models generate more vulnerable code, to build offensive tooling, or for any non-defensive purpose. Steering directions derived from it are sign-reversible, and only the safety-promoting direction should be applied.

## Citation

```bibtex
@misc{yan2026interpretingsteeringsafecorrect,
      title={Interpreting and Steering for Safe and Correct Code Generation},
      author={Hao Yan and Ziyu Yao},
      year={2026},
      eprint={2608.30025},
      archivePrefix={arXiv},
      primaryClass={cs.AI},
      url={https://arxiv.org/abs/2608.30025},
}
```
