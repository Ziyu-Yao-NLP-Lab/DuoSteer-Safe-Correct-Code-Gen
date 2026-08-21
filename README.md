# Interpreting and Steering for Safe and Correct Code Generation

Code and data for the paper *"Interpreting and Steering for Safe and Correct Code Generation."*

Large language models frequently generate source code containing vulnerabilities, yet little work studies the internal mechanisms that distinguish safe from vulnerable generation. This work performs a mechanistic interpretation of code LLMs and turns the insights into actionable steering strategies for safer code generation. We introduce **CodeSec-Pairs**, a dataset of 4,260 Python safe-vs-vulnerable contrastive code pairs sampled from Llama-3.1-8B-Instruct and labeled with CodeQL static analysis; using it, we localize the layers and attention heads that encode code safety (linear probing and causal head knockout) and experiment with inference-time steering strategies. Our main method, **DuoSteer**, is a double-steering approach that simultaneously applies a safety direction and a code-correctness direction to attention heads. Over five vulnerability types (CWEs), DuoSteer reduces the vulnerability rate by 26.9% on average while improving functional correctness by 7.5%, outperforming other steering variants as well as prompting and supervised fine-tuning baselines, and the pattern replicates on Qwen-2.5-Coder-7B-Instruct.

This repository contains the full experimental pipeline:

1. **CodeSec-Pairs construction**: sample code generations from an LLM, label them with CodeQL static analysis, and build matched safe-vs-vulnerable contrastive pairs annotated with structural distance and fix mechanism.
2. **Localization**: extract per-layer and per-attention-head representations, train linear probes, and run causal head knockout to find the heads that drive safe-vs-vulnerable generation.
3. **Steering**: build mean-difference steering vectors and apply them at inference time, including **DuoSteer**, which simultaneously injects a safety direction and a correctness direction at their respective causally identified head sets.
4. **Evaluation**: CodeQL vulnerability rate, GPT-4.1 functional-correctness judge, and SecCodePLT execution-based unit tests.

## Setup

**Python** (3.9 or newer):

```bash
pip install -r requirements.txt
```

**Models.** Llama-3.1-8B-Instruct is a gated Hugging Face repository; log in with `huggingface-cli login` first. Representation extraction and steering need one GPU able to hold the model in `bfloat16` (an 80 GB A100 was used).

**CodeQL.** Install the [CodeQL CLI](https://codeql.github.com) and the `codeql/python-queries` pack.

```bash
export CODEQL_BIN=/path/to/codeql/codeql
export CODEQL_QLPACK=/path/to/codeql/qlpacks/codeql/python-queries/<version>/Security
export CODEQL_SUITE_ALL=/path/to/codeql/qlpacks/codeql/python-queries/<version>/codeql-suites/python-security-extended.qls
```

The query pack version used in our experiments is `1.8.0`.

**OpenAI API** (GPT-4.1 correctness judge and pair annotation, via the Batch API):

```bash
export OPENAI_API_KEY=...
```