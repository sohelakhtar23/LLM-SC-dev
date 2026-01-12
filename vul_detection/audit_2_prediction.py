import os
import json
import time
import argparse
from typing import Any, Dict, List, Optional
from datetime import datetime

import requests


# ---------- Ollama helpers ----------

def ollama_list_models(base_url: str, timeout: int = 10) -> List[str]:
    r = requests.get(f"{base_url}/tags", timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return [m["name"] for m in data.get("models", []) if m.get("name")]


def _safe_json_parse(text: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(text)
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        chunk = text[start : end + 1]
        try:
            return json.loads(chunk)
        except Exception:
            return None
    return None


def ollama_generate_structured(
    base_url: str,
    model: str,
    prompt: str,
    schema: Dict[str, Any],
    timeout: int = 120,
    temperature: float = 0.0,
    keep_alive: str = "30m",
    max_retries: int = 2,
    max_total_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """
    POST /api/generate with stream:false and JSON schema in `format`.

    Timeout behavior:
    - `timeout` is the per-request timeout passed to `requests.post`.
    - `max_total_seconds` caps the *overall* wall-clock time spent on this call,
      including retries and backoff. This prevents a single slow file from
      blocking the whole pipeline for many minutes.
    """
    url = f"{base_url}/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": schema,
        "keep_alive": keep_alive,
        "options": {
            "temperature": temperature,
        },
    }

    # If not provided, cap total time to `timeout` so retries don't multiply runtime.
    if max_total_seconds is None:
        max_total_seconds = float(timeout)

    t_start = time.perf_counter()
    deadline = t_start + float(max_total_seconds)

    last_err = None
    for attempt in range(max_retries + 1):
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError(
                f"Overall timeout exceeded ({max_total_seconds:.1f}s) for model={model}"
            )

        # Ensure each attempt respects the overall deadline.
        post_timeout = min(float(timeout), max(0.1, remaining))

        try:
            r = requests.post(url, json=payload, timeout=post_timeout)
            r.raise_for_status()
            out = r.json()
            raw = out.get("response", "").strip()

            # Sometimes models wrap JSON in text; try to extract the first JSON object.
            parsed = _safe_json_parse(raw)
            if parsed is not None:
                return parsed

            # Retry with stricter prompt if parsing failed
            last_err = f"Could not parse JSON from model output: {raw[:200]}..."
            payload["prompt"] = prompt + "\n\nIMPORTANT: Return ONLY valid JSON matching the schema. No extra text."
        except Exception as e:
            last_err = str(e)

        # Backoff, but don't sleep past the overall deadline
        if attempt < max_retries:
            backoff = 0.8 * (attempt + 1)
            remaining = deadline - time.perf_counter()
            if remaining > 0:
                time.sleep(min(backoff, remaining))

    raise RuntimeError(f"Ollama generate failed for model={model}: {last_err}")


# ---------- Dataset helpers ----------

def iter_sol_files(root_dir: str) -> List[str]:
    sols = []
    for root, _, files in os.walk(root_dir):
        for fn in files:
            if fn.lower().endswith(".sol"):
                sols.append(os.path.join(root, fn))
    sols.sort()
    return sols


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf8") as f:
        return f.read()



def normalize_vuln_type(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower()
    mapping = {
        "reentrancy": "reentrancy",
        "bad randomness": "bad_randomness",
        "bad_randomness": "bad_randomness",
        "randomness": "bad_randomness",
        "access control": "access_control",
        "access_control": "access_control",
        "unchecked_low_level_calls": "unchecked_ll_calls",
        "unchecked low level calls": "unchecked_ll_calls",
        "unchecked_low_level_call": "unchecked_ll_calls",
        "unchecked low level call": "unchecked_ll_calls",
        "none": None,
        "null": None,
    }
    return mapping.get(s, s)



# ---------- Prompt + schema ----------

OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "vulnerability_type": {
            "type": ["string", "null"],
            "enum": ["reentrancy", "bad_randomness", "access_control", "unchecked_ll_calls", None],
        },
        "line": {"type": ["integer", "null"]},
        "explanation": {"type": "string"},
    },
    "required": ["vulnerability_type", "line", "explanation"],
}


def build_prompt(code: str) -> str:
    return f"""You are a Solidity security auditor.

Task:
- Analyze the contract below and decide whether it contains ONE vulnerability among:
  1) reentrancy
  2) bad_randomness (predictable randomness like block.timestamp, blockhash, block.number, etc.)
  3) access_control (missing/incorrect authorization checks for privileged actions)
  4) unchecked_ll_calls (unchecked low-level calls)
- If none of these vulnerabilities are present, output vulnerability_type = null and line = null.
- If a vulnerability is present, output the SINGLE most representative line number (1-indexed) in the original source file below.
- Keep explanation brief (1–3 sentences).
- Output MUST be valid JSON matching the schema (no markdown, no extra text).

CONTRACT:
```solidity
{code}
```
Please provide your answer in JSON format as per the schema."""

# ---------- Main pipeline ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset_dir", default="dataset_clean")
    ap.add_argument("--base_url", default="http://localhost:11434/api")
    ap.add_argument("--models", nargs="*", default=None)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--keep_alive", default="30m")
    args = ap.parse_args()

    # Determine models
    if args.models:
        models = args.models
    else:
        models = ollama_list_models(args.base_url)
        if not models:
            raise RuntimeError("No models found from /api/tags. Is Ollama running and do you have models installed?")

    sol_files = iter_sol_files(args.dataset_dir)
    if not sol_files:
        raise RuntimeError(f"No .sol files found under {args.dataset_dir}")

    total_t0 = time.perf_counter()

    # Results grouped by model name (as you requested)
    results_by_model: Dict[str, List[Dict[str, Any]]] = {}
    timing: Dict[str, float] = {}

    for model in models:
        model_t0 = time.perf_counter()
        print(f"\n=== Running model: {model} (files={len(sol_files)}) ===")

        model_outputs: List[Dict[str, Any]] = []

        for idx, sol_path in enumerate(sol_files, start=1):
            code = read_text(sol_path)
            n_lines = len(code.splitlines())
            rel = os.path.relpath(sol_path, args.dataset_dir).replace("\\", "/")

            prompt = build_prompt(code)

            t0 = time.perf_counter()
            timed_out = False
            err_msg = None
            try:
                pred = ollama_generate_structured(
                    base_url=args.base_url,
                    model=model,
                    prompt=prompt,
                    schema=OUTPUT_SCHEMA,
                    timeout=args.timeout,
                    temperature=0.0,
                    keep_alive=args.keep_alive,
                    max_retries=2,
                    max_total_seconds=args.timeout,
                )
            except TimeoutError as e:
                timed_out = True
                err_msg = str(e)
                pred = {
                    "vulnerability_type": None,
                    "line": None,
                    "explanation": f"Timed out after {args.timeout}s.",
                }
            except Exception as e:
                err_msg = str(e)
                pred = {
                    "vulnerability_type": None,
                    "line": None,
                    "explanation": f"Error ({type(e).__name__}): {err_msg[:160]}",
                }

            dt = time.perf_counter() - t0

            vt = normalize_vuln_type(pred.get("vulnerability_type"))
            line_raw = pred.get("line")
            try:
                line = int(line_raw) if line_raw is not None else None
            except Exception:
                line = None
            explanation = str(pred.get("explanation", "")).strip()

            model_outputs.append({
                "file": rel,
                "prediction": {
                    "vulnerability_type": vt,
                    "line": line,
                    "explanation": explanation,
                },
                "meta": {
                    "lines_in_file": n_lines,
                    "seconds": round(dt, 3),
                    "timed_out": timed_out,
                    "error": err_msg,
                }
            })

            status = "TIMEOUT" if timed_out else f"{vt} @ {line}"
            print(f"[{idx:02d}/{len(sol_files)}] {rel} -> {status}  ({dt:.2f}s)")

        model_dt = time.perf_counter() - model_t0
        results_by_model[model] = model_outputs
        timing[model] = model_dt

        print(f"=== Model done: {model} in {model_dt:.2f}s ===")

    total_dt = time.perf_counter() - total_t0

    # Add timing + run metadata (kept separate so model keys stay clean)
    output = dict(results_by_model)
    output["_timing_seconds"] = {k: round(v, 3) for k, v in timing.items()}
    output["_total_seconds"] = round(total_dt, 3)

    json_output_file_name = "llm_vuln_results" + datetime.now().strftime("%b%d_%H_%M_%S" + ".json")
    with open(json_output_file_name, "w", encoding="utf8") as f:
        json.dump(output, f, indent=2)

    print(f"\nSaved: {json_output_file_name}")
    print(f"Total time: {total_dt:.2f}s")


if __name__ == "__main__":
    main()
