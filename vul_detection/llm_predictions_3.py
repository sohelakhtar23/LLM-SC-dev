import os
import json
import time
import argparse
from typing import Any, Dict, List, Optional

import requests


def get_ollama_models(base_url: str = "http://localhost:11434") -> List[str]:
    """Fetch list of available Ollama models."""
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=10)
        response.raise_for_status()
        data = response.json()
        return [model["name"] for model in data.get("models", [])]
    except Exception as e:
        print(f"Error fetching models: {e}")
        return []


def call_ollama_generate(
    base_url: str,
    model: str,
    prompt: str,
    timeout: int = 180,
    temperature: float = 0.0
) -> str:
    """Call Ollama's generate API and return the response text."""
    url = f"{base_url}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        result = response.json()
        return result.get("response", "").strip()
    except Exception as e:
        raise RuntimeError(f"Ollama API call failed: {str(e)}")


def extract_json_from_response(text: str) -> Optional[Dict[str, Any]]:
    """Extract JSON from model response, handling markdown code blocks."""
    # Try direct parsing first
    try:
        return json.loads(text)
    except:
        pass
    
    # Remove markdown code blocks if present
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json or ```)
        lines = lines[1:]
        # Remove last line if it's ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    
    # Try parsing again
    try:
        return json.loads(text)
    except:
        pass
    
    # Try to find JSON object in text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except:
            pass
    
    return None


def build_vulnerability_prompt(contract_code: str) -> str:
    """Build the prompt for vulnerability detection."""
    return f"""You are an expert smart contract security auditor. Analyze the following Solidity smart contract and identify the MOST PROMINENT vulnerability present.

Smart Contract Code:
```solidity
{contract_code}
```

Instructions:
1. Identify the SINGLE most critical/prominent vulnerability in this contract
2. Provide the specific line number(s) where the vulnerability occurs (1-indexed)
3. Categorize the vulnerability into ONE of these types:
   - reentrancy
   - access_control
   - arithmetic
   - unchecked_low_level_calls
   - denial_of_service
   - bad_randomness
   - front_running
   - time_manipulation
   - short_addresses
   - other

4. Provide a brief explanation (1-3 sentences)

IMPORTANT: Respond ONLY with a valid JSON object in this exact format (no markdown, no code blocks, no additional text):
{{"vulnerability_type": "type from list above", "lines": [line_number], "explanation": "brief explanation"}}

If no vulnerability is found, respond with:
{{"vulnerability_type": "none", "lines": [], "explanation": "no vulnerability detected"}}
"""


def normalize_vulnerability_type(vuln_type: Any) -> Optional[str]:
    """Normalize vulnerability type names."""
    if vuln_type is None:
        return None
    
    v = str(vuln_type).strip().lower().replace(" ", "_")
    
    # Mapping for common variations
    mapping = {
        "reentrancy": "reentrancy",
        "access_control": "access_control",
        "accesscontrol": "access_control",
        "arithmetic": "arithmetic",
        "unchecked_low_level_calls": "unchecked_low_level_calls",
        "unchecked_ll_calls": "unchecked_low_level_calls",
        "uncheckedlowlevelcalls": "unchecked_low_level_calls",
        "denial_of_service": "denial_of_service",
        "denialofservice": "denial_of_service",
        "dos": "denial_of_service",
        "bad_randomness": "bad_randomness",
        "badrandomness": "bad_randomness",
        "randomness": "bad_randomness",
        "front_running": "front_running",
        "frontrunning": "front_running",
        "time_manipulation": "time_manipulation",
        "timemanipulation": "time_manipulation",
        "short_addresses": "short_addresses",
        "shortaddresses": "short_addresses",
        "other": "other",
        "none": None,
    }
    
    return mapping.get(v, v)


def find_solidity_files(dataset_dir: str) -> List[str]:
    """Recursively find all .sol files in dataset directory."""
    sol_files = []
    for root, _, files in os.walk(dataset_dir):
        for filename in files:
            if filename.lower().endswith(".sol"):
                sol_files.append(os.path.join(root, filename))
    return sorted(sol_files)


def read_file(filepath: str) -> str:
    """Read file content."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def process_contract(
    base_url: str,
    model: str,
    contract_path: str,
    dataset_dir: str,
    timeout: int = 180
) -> Dict[str, Any]:
    """Process a single contract file with the model."""
    # Read contract
    contract_code = read_file(contract_path)
    num_lines = len(contract_code.splitlines())
    relative_path = os.path.relpath(contract_path, dataset_dir)
    
    # Build prompt
    prompt = build_vulnerability_prompt(contract_code)
    
    # Call model
    start_time = time.time()
    timed_out = False
    error_msg = None
    
    try:
        response_text = call_ollama_generate(base_url, model, prompt, timeout)
        parsed = extract_json_from_response(response_text)
        
        if parsed is None:
            error_msg = f"Failed to parse JSON from response: {response_text[:200]}"
            prediction = {
                "vulnerability_type": None,
                "lines": [],
                "explanation": "Failed to parse model response"
            }
        else:
            prediction = parsed
            
    except Exception as e:
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            timed_out = True
        prediction = {
            "vulnerability_type": None,
            "lines": [],
            "explanation": f"Error: {error_msg[:100]}"
        }
    
    elapsed = time.time() - start_time
    
    # Normalize results
    vuln_type = normalize_vulnerability_type(prediction.get("vulnerability_type"))
    lines = prediction.get("lines", [])
    if not isinstance(lines, list):
        lines = [lines] if lines is not None else []
    explanation = prediction.get("explanation", "")
    
    return {
        "file": relative_path,
        "prediction": {
            "vulnerability_type": vuln_type,
            "lines": lines,
            "explanation": str(explanation).strip()
        },
        "meta": {
            "lines_in_file": num_lines,
            "time_seconds": round(elapsed, 2),
            "timed_out": timed_out,
            "error": error_msg
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM vulnerability detection on SmartBugs dataset"
    )
    parser.add_argument(
        "--dataset_dir",
        type=str,
        default="dataset_clean",
        help="Path to dataset directory containing .sol files"
    )
    parser.add_argument(
        "--base_url",
        type=str,
        default="http://localhost:11434",
        help="Ollama API base URL"
    )
    parser.add_argument(
        "--models",
        nargs="*",
        default=None,
        help="List of model names to evaluate (if not provided, uses all available models)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout in seconds for each model call"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output/llm_vuln_results.json",
        help="Output JSON file path"
    )
    
    args = parser.parse_args()
    
    # Get models
    if args.models:
        models = args.models
    else:
        models = get_ollama_models(args.base_url)
        if not models:
            print("ERROR: No models found. Make sure Ollama is running and you have models installed.")
            print("You can install a model with: ollama pull <model_name>")
            return
    
    print(f"Found models: {', '.join(models)}")
    
    # Find all Solidity files
    sol_files = find_solidity_files(args.dataset_dir)
    if not sol_files:
        print(f"ERROR: No .sol files found in {args.dataset_dir}")
        return
    
    print(f"Found {len(sol_files)} Solidity files")
    
    # Process all files for each model
    results = {}
    timing = {}
    
    total_start = time.time()
    
    for model in models:
        print(f"\n{'='*60}")
        print(f"Evaluating model: {model}")
        print(f"{'='*60}")
        
        model_start = time.time()
        model_results = []
        
        for idx, sol_path in enumerate(sol_files, 1):
            print(f"[{idx}/{len(sol_files)}] Processing: {os.path.basename(sol_path)}...", end=" ")
            
            result = process_contract(
                args.base_url,
                model,
                sol_path,
                args.dataset_dir,
                args.timeout
            )
            
            model_results.append(result)
            
            vuln = result["prediction"]["vulnerability_type"]
            lines = result["prediction"]["lines"]
            elapsed = result["meta"]["time_seconds"]
            status = f"{vuln} @ lines {lines}" if vuln else "none"
            print(f"{status} ({elapsed:.1f}s)")
        
        model_elapsed = time.time() - model_start
        results[model] = model_results
        timing[model] = round(model_elapsed, 2)
        
        print(f"\nModel '{model}' completed in {model_elapsed:.1f}s")
    
    total_elapsed = time.time() - total_start
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Save results
    output_data = {
        **results,
        "_metadata": {
            "total_files": len(sol_files),
            "models_evaluated": len(models),
            "timing_seconds": timing,
            "total_time_seconds": round(total_elapsed, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"Results saved to: {args.output}")
    print(f"Total evaluation time: {total_elapsed:.1f}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()