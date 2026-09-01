"""
LLaMA inference without pipeline: load model and tokenizer explicitly for
full control (e.g. modifying residual connections later).

Example: modify residual network before generation:
  model, tokenizer = load_model_and_tokenizer("meta-llama/Llama-3.2-3B-Instruct")
  # e.g. model.model.layers[i] for decoder blocks, or add hooks / new modules
  text = generate_response(model, tokenizer, "Your prompt here")
"""
# --- repo path setup: allow running this script from any directory ---
import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parents[1]
for _d in ("common", "dataset_construction"):
    _p = _REPO_ROOT / _d
    if _p.is_dir() and str(_p) not in _sys.path:
        _sys.path.insert(0, str(_p))
# ---------------------------------------------------------------------
from transformers import AutoModelForCausalLM, AutoTokenizer
from typing import Any, Dict, List, Optional, Tuple, Union
from utils import read_jsonl, write_jsonl

import argparse
import torch



def get_device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_model_and_tokenizer(
    model_type: str,
    *,
    torch_dtype: Optional[torch.dtype] = None,
    device: Optional[torch.device] = None,
    **model_kwargs: Any,
) -> Tuple[AutoModelForCausalLM, AutoTokenizer]:
    """Load LLaMA model and tokenizer. Returns (model, tokenizer) so you can
    modify the model (e.g. residual network) before calling generate."""
    if device is None:
        device = get_device()
    if torch_dtype is None:
        torch_dtype = torch.float16 if device.type == "cuda" else torch.float32

    tokenizer = AutoTokenizer.from_pretrained(model_type, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_type,
        torch_dtype=torch_dtype,
        **model_kwargs,
    )
    model = model.to(device)
    model.eval()
    return model, tokenizer


def generate_response(
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    message: str,
    *,
    device: Optional[torch.device] = None,
    max_new_tokens: int = 2048,
    num_return_sequences: int = 1,
    do_sample: bool = False,
    temperature: float = 1.0,
    top_p: float = 1.0,
    top_k: int = 0,
    pad_token_id: Optional[int] = None,
    eos_token_id: Optional[int] = None,
    **generate_kwargs: Any,
) -> Union[str, List[str]]:
    """Run the model on a prompt and return generated text (no prompt).
    When num_return_sequences > 1, returns a list of strings in one forward pass."""
    if device is None:
        device = next(model.parameters()).device

    inputs = tokenizer(
        message,
        return_tensors="pt",
        truncation=True,
        max_length=model.config.max_position_embeddings,
        padding=False,
    )
    input_ids = inputs["input_ids"].to(device)
    attention_mask = inputs.get("attention_mask")
    if attention_mask is not None:
        attention_mask = attention_mask.to(device)

    if pad_token_id is None and tokenizer.pad_token_id is not None:
        pad_token_id = tokenizer.pad_token_id
    if pad_token_id is None:
        pad_token_id = tokenizer.eos_token_id
    if eos_token_id is None:
        eos_token_id = tokenizer.eos_token_id

    kwargs: Dict[str, Any] = dict(
        attention_mask=attention_mask,
        max_new_tokens=max_new_tokens,
        num_return_sequences=num_return_sequences,
        do_sample=do_sample,
        pad_token_id=pad_token_id,
        eos_token_id=eos_token_id,
        **generate_kwargs,
    )
    if do_sample:
        kwargs["temperature"] = temperature
        kwargs["top_p"] = top_p
        if top_k > 0:
            kwargs["top_k"] = top_k

    with torch.no_grad():
        out = model.generate(input_ids, **kwargs)

    prompt_len = input_ids.shape[1]
    if num_return_sequences == 1:
        new_token_ids = out[0][prompt_len:]
        return tokenizer.decode(new_token_ids, skip_special_tokens=True).strip()
    responses: List[str] = []
    for j in range(num_return_sequences):
        new_token_ids = out[j][prompt_len:]
        responses.append(tokenizer.decode(new_token_ids, skip_special_tokens=True).strip())
    return responses


def request_response(
    input_file: str,
    output_file: str,
    model_type: str,
    *,
    max_new_tokens: int = 2048,
    prompt_key: str = "prompt",
    num_samples: int = 1,
    do_sample: bool = False,
    temperature: float = 1.0,
    top_p: float = 1.0,
    top_k: int = 0,
) -> None:
    data = read_jsonl(input_file)
    device = get_device()
    model, tokenizer = load_model_and_tokenizer(model_type, device=device)

    for i, dt in enumerate(data):
        if 'predicted_code' in dt:
            continue
        message = dt.get(prompt_key) or dt.get("messages")
        if message is None:
            raise KeyError(f"Each item must have '{prompt_key}' or 'messages'. Keys: {list(dt.keys())}")
        if isinstance(message, list):
            message = tokenizer.apply_chat_template(
                message,
                tokenize=False,
                add_generation_prompt=True,
            )
        result = generate_response(
            model,
            tokenizer,
            message,
            device=device,
            max_new_tokens=max_new_tokens,
            num_return_sequences=num_samples,
            do_sample=do_sample,
            temperature=temperature,
            top_p=top_p,
            top_k=top_k,
        )
        dt["predicted_code"] = result if isinstance(result, list) else [result]
        print(f"Completed {i + 1}/{len(data)}")
        write_jsonl(data, output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLaMA inference (no pipeline).")
    parser.add_argument("-i", "--input_file", type=str, default="data/processed_secure_data.jsonl", help="Input JSONL file.")
    parser.add_argument("-o", "--output_file", type=str, default="data/llama3.2_3B_secure_output.jsonl", help="Output JSONL file.")
    parser.add_argument("-m", "--model_type", type=str, default="meta-llama/Llama-3.1-8B-Instruct", help="Huggingface model id.")
    parser.add_argument("--max_new_tokens", type=int, default=2048, help="Max new tokens to generate.")
    parser.add_argument("--prompt_key", type=str, default="messages", help="Key for prompt text in each item (or use 'messages' for chat).")
    parser.add_argument("--num_samples", "-n", type=int, default=1, help="Number of samples per question (list when > 1).")
    parser.add_argument("--do_sample", action="store_true", help="Enable sampling.")
    parser.add_argument("--temperature", type=float, default=1.0, help="Sampling temperature.")
    parser.add_argument("--top_p", type=float, default=1.0, help="Nucleus sampling top_p.")
    parser.add_argument("--top_k", type=int, default=0, help="Top-k sampling (0 = disabled).")
    args = parser.parse_args()

    request_response(
        args.input_file,
        args.output_file,
        args.model_type,
        max_new_tokens=args.max_new_tokens,
        prompt_key=args.prompt_key,
        num_samples=args.num_samples,
        do_sample=args.do_sample,
        temperature=args.temperature,
        top_p=args.top_p,
        top_k=args.top_k,
    )
