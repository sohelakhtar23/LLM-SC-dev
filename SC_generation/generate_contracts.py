import os
import pandas as pd
import re
import requests
import json
import shutil
import traceback
import time
from typing import List, Tuple, Dict, Any
from yaspin import yaspin
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# Configuration
NUM_ITERATIONS = 2
MODELS = [
    "llama3.2:1b",
    # "gemma3:1b",
    # "deepseek-coder:1.3b"
    ]
# MODELS = [
#     "gpt-oss:20b",
#     "gemma3:27b",
#     "mistral-small:24b",
#     "llama3.1:8b",
#     "qwen2.5-coder:7b",
#     "deepseek-coder:6.7b"
# ]
OLLAMA_TIMEOUT = 180
MAX_RETRIES = 2
REQUEST_TIMEOUT = 180


class ContractGenerator:
    def __init__(self):
        self.output_dir = "output"
        self.generation_results = {}
        self.folder_mapping = {}
        self.statistics = {
            "total_prompts": 0,
            "successful_generations": 0,
            "failed_generations": 0,
            "total_time": 0,
            "model_times": {}
        }

    def clean_repository(self) -> None:
        """Remove existing output directory and create fresh structure."""
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"[INFO] Output directory cleaned and created: {self.output_dir}\n")

    def load_dataset(self, dataset_path: str) -> List[Tuple[str, str, str]]:
        """Load prompts from CSV file."""
        try:
            df = pd.read_csv(dataset_path, encoding='latin1')
            num_prompts = df.shape[0]
            
            print(f"[DATASET] Loading: {dataset_path}")
            print(f"[DATASET] Total prompts: {num_prompts}\n")
            
            dataset = []
            print("[PROMPTS]")
            for i in range(num_prompts):
                task = df.iat[i, 0]  # Exercise column
                spec = df.iat[i, 1]  # Specification column
                dataset.append((task, spec))
                print(f"  [{i+1}] {task}: {len(spec)} chars")
            
            print()
            self.statistics["total_prompts"] = num_prompts
            return dataset
            
        except Exception as e:
            print(f"[ERROR] Failed to load dataset: {e}")
            raise

    def sanitize_filename(self, name: str) -> str:
        """Remove invalid characters for Windows file paths."""
        return re.sub(r'[<>:"/\\|?*]', '_', name)

    def call_ollama_api(self, model: str, prompt: str, temperature: float = 0.2, 
                       retry_count: int = 0) -> Dict[str, Any]:
        """Call Ollama API with timeout and retry logic."""
        url = "http://localhost:11434/api/generate"
        headers = {'Content-Type': 'application/json'}
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "30m",
            "options": {"temperature": temperature}
        }

        try:
            response = requests.post(
                url, 
                headers=headers, 
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
                
        except requests.exceptions.Timeout:
            if retry_count < MAX_RETRIES:
                print(f"\n[WARNING] Timeout occurred, retrying ({retry_count + 1}/{MAX_RETRIES})...")
                time.sleep(2)
                return self.call_ollama_api(model, prompt, temperature, retry_count + 1)
            else:
                raise TimeoutError(f"Request timed out after {REQUEST_TIMEOUT} seconds")
                
        except Exception as e:
            if retry_count < MAX_RETRIES:
                print(f"\n[WARNING] Request failed: {e}, retrying ({retry_count + 1}/{MAX_RETRIES})...")
                time.sleep(2)
                return self.call_ollama_api(model, prompt, temperature, retry_count + 1)
            else:
                raise

    def extract_solidity_code(self, text: str) -> str:
        """Extract Solidity code from markdown code blocks."""
        pattern = re.compile(r'```(.*?)```', re.DOTALL)
        matches = pattern.findall(text)
        
        extracted_code = []
        for match in matches:
            match = match.strip()
            lines = match.split('\n')
            
            if lines and lines[0].strip().lower() == "solidity":
                lines = lines[1:]
            
            if not lines:
                continue
            
            code = '\n'.join(lines)
            
            if not code.strip().startswith('// SPDX-License-Identifier:'):
                code = '// SPDX-License-Identifier: UNLICENSED\n' + code
            
            extracted_code.append(code)
        
        return '\n\n'.join(extracted_code) if extracted_code else text

    def generate_contract(self, model: str, prompt_data: Tuple[str, str], 
                         iteration: int, contract_dir: str) -> Dict[str, Any]:
        """Generate a single contract."""
        prompt_name, specification = prompt_data
        result = {
            "response": "",
            "solidity_code": "",
            "timing": {},
            "error": None
        }
        
        # Simple, clear prompt focusing on essentials
        full_prompt = (
            f"You are an expert Solidity developer. Generate a complete, production-ready smart contract.\n"
            f"Use Solidity ^0.8.x. Focus on correctness, security, and clarity. Optimize for gas efficiency\n\n"
            f"TASK: {prompt_name}\n"
            f"SPECIFICATION: {specification}\n\n"
            f"OUTPUT FORMAT:\n"
            f"- Provide ONLY the Solidity code\n"
            f"- NO explanations, NO markdown formatting, NO comments outside the code\n"
            f"- Start directly with the SPDX license or pragma statement\n"
        )
        
        generation_start = time.time()
        try:
            api_response = self.call_ollama_api(model, full_prompt)
            generation_time = time.time() - generation_start
            
            result["timing"]["generation_seconds"] = round(generation_time, 2)
            result["response"] = api_response.get("response", "")
            result["timing"]["total_duration_ns"] = api_response.get("total_duration", 0)
            
            txt_path = os.path.join(contract_dir, f"{iteration}.txt")
            with open(txt_path, 'w', encoding="utf-8") as f:
                f.write(result["response"])
            
            solidity_code = self.extract_solidity_code(result["response"])
            sol_path = os.path.join(contract_dir, f"{iteration}.sol")
            with open(sol_path, 'w', encoding="utf-8") as f:
                f.write(solidity_code)
            
            result["solidity_code"] = solidity_code
            self.statistics["successful_generations"] += 1
            
        except Exception as e:
            generation_time = time.time() - generation_start
            result["timing"]["generation_seconds"] = round(generation_time, 2)
            result["error"] = str(e)
            result["traceback"] = traceback.format_exc()
            self.statistics["failed_generations"] += 1
        
        return result

    def run_generation(self, dataset_path: str = "prompts_2nd.csv") -> None:
        """Main generation execution."""
        print("=" * 80)
        print(" " * 20 + "SOLIDITY CONTRACT GENERATION")
        print("=" * 80 + "\n")
        
        start_time = time.time()
        
        self.clean_repository()
        dataset = self.load_dataset(dataset_path)
        
        print(f"[MODELS] {MODELS}")
        print(f"[CONFIG] Iterations per prompt: {NUM_ITERATIONS}")
        print(f"[CONFIG] LLM timeout: {OLLAMA_TIMEOUT}s ({OLLAMA_TIMEOUT//60} minutes)")
        print(f"[CONFIG] Max retries: {MAX_RETRIES}\n")
        
        for model in MODELS:
            model_start = time.time()
            model_dir = self.sanitize_filename(model)
            model_output_dir = os.path.join(self.output_dir, model_dir)
            os.makedirs(model_output_dir, exist_ok=True)
            
            self.folder_mapping[model] = {
                "folder_name": model_dir,
                "prompts": {}
            }
            
            print(f"\n{'='*80}")
            print(f"[MODEL] Processing: {model}")
            print(f"{'='*80}\n")
            
            self.generation_results[model] = {}
            total_contracts = 0
            
            with yaspin(text="Initializing...") as spinner:
                for prompt_idx, prompt_data in enumerate(dataset, 1):
                    prompt_name = prompt_data[0]
                    prompt_dir = self.sanitize_filename(prompt_name)
                    contract_dir = os.path.join(model_output_dir, prompt_dir)
                    os.makedirs(contract_dir, exist_ok=True)
                    
                    self.folder_mapping[model]["prompts"][prompt_name] = {
                        "folder_name": prompt_dir,
                        "path": os.path.join(model_dir, prompt_dir)
                    }
                    
                    self.generation_results[model][prompt_name] = {}
                    
                    for iteration in range(NUM_ITERATIONS):
                        iteration_num = iteration + 1
                        spinner.text = (
                            f"[{prompt_idx}/{len(dataset)}] {prompt_name} "
                            f"| Iteration {iteration_num}/{NUM_ITERATIONS}"
                        )
                        
                        iteration_start = time.time()
                        
                        try:
                            result = self.generate_contract(
                                model, prompt_data, iteration, contract_dir
                            )
                            self.generation_results[model][prompt_name][f"iteration_{iteration}"] = result
                            
                            iteration_time = time.time() - iteration_start
                            status = "✓" if result.get("error") is None else "✗"
                            
                            spinner.write(
                                f"  {status} [{prompt_idx}/{len(dataset)}] {prompt_name} "
                                f"[Iter {iteration_num}] - {iteration_time:.1f}s "
                                f"(gen: {result['timing']['generation_seconds']}s)"
                            )
                            
                        except Exception as e:
                            error_result = {
                                "error": str(e),
                                "traceback": traceback.format_exc(),
                                "timing": {"generation_seconds": 0}
                            }
                            self.generation_results[model][prompt_name][f"iteration_{iteration}"] = error_result
                            spinner.write(
                                f"  ✗ [{prompt_idx}/{len(dataset)}] {prompt_name} "
                                f"[Iter {iteration_num}] - ERROR: {str(e)}"
                            )
                        
                        total_contracts += 1
                
                spinner.ok(f"✓ Completed {total_contracts} contracts for {model}")
            
            model_time = time.time() - model_start
            self.statistics["model_times"][model] = {
                "seconds": round(model_time, 2),
                "minutes": round(model_time / 60, 2)
            }
            print(f"\n[MODEL TIME] {model}: {model_time:.1f}s ({model_time/60:.1f} minutes)")
        
        total_time = time.time() - start_time
        self.statistics["total_time"] = round(total_time, 2)
        self.print_summary()
        self.save_results()

    def save_results(self) -> None:
        """Save generation results to JSON file."""
        results_path = os.path.join(self.output_dir, "generation_results.json")
        summary_path = os.path.join(self.output_dir, "generation_summary.json")
        
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(self.generation_results, f, indent=2)
        
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "statistics": self.statistics,
                "folder_mapping": self.folder_mapping,
                "configuration": {
                    "models": MODELS,
                    "iterations": NUM_ITERATIONS,
                    "timeout": OLLAMA_TIMEOUT
                }
            }, f, indent=2)
        
        print(f"\n[SAVED] Results: {results_path}")
        print(f"[SAVED] Summary: {summary_path}")

    def print_summary(self) -> None:
        """Print generation summary statistics."""
        print("\n" + "=" * 80)
        print(" " * 30 + "SUMMARY")
        print("=" * 80)
        print(f"\n[STATISTICS]")
        print(f"  Total prompts:              {self.statistics['total_prompts']}")
        print(f"  Successful generations:     {self.statistics['successful_generations']}")
        print(f"  Failed generations:         {self.statistics['failed_generations']}")
        
        if self.statistics['successful_generations'] > 0:
            success_rate = (self.statistics['successful_generations'] / 
                          (self.statistics['successful_generations'] + self.statistics['failed_generations']) * 100)
            print(f"  Generation success rate:    {success_rate:.1f}%")
        
        print(f"\n[TIMING]")
        print(f"  Total execution time:       {self.statistics['total_time']:.1f}s")
        print(f"                              ({self.statistics['total_time']/60:.1f} minutes)")
        
        if self.statistics['model_times']:
            print(f"\n[MODEL TIMES]")
            for model, times in self.statistics['model_times'].items():
                print(f"  {model:25} {times['seconds']:.1f}s ({times['minutes']:.1f} min)")
        
        print("=" * 80 + "\n")


if __name__ == '__main__':
    generator = ContractGenerator()
    try:
        # generator.run_generation("prompts_2nd.csv")
        generator.run_generation("temp/prompts2_temp.csv")
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Generation stopped by user")
    except Exception as e:
        print(f"\n\n[ERROR] Generation failed: {e}")
        traceback.print_exc()