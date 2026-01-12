import os
import pandas as pd
import re
import requests
import json
import subprocess
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
    "gemma3:1b",
    "deepseek-coder:1.3b"
    ]
OLLAMA_TIMEOUT = 180  # 3 minutes in seconds
MAX_RETRIES = 2
REQUEST_TIMEOUT = 180  # 3 minutes for HTTP request

class SolidityBenchmark:
    def __init__(self):
        self.output_dir = "output"
        self.extracted_tests_dir = os.path.join(self.output_dir, "extracted_tests")
        self.results = {}
        self.statistics = {
            "total_prompts": 0,
            "successful_generations": 0,
            "failed_generations": 0,
            "successful_compilations": 0,
            "failed_compilations": 0,
            "total_time": 0,
            "model_times": {}
        }

    def clean_repository(self) -> None:
        """Remove existing output directory and create fresh structure."""
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.extracted_tests_dir, exist_ok=True)
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
                name = df.iat[i, 0]
                task = df.iat[i, 1]
                spec = df.iat[i, 2] if df.shape[1] > 2 else ""
                dataset.append((name, task, spec))
                print(f"  [{i+1}] {name}: {len(task)} chars")
            
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
        """
        Call Ollama API with timeout and retry logic.
        
        Args:
            model: Model name to use
            prompt: Prompt text
            temperature: Temperature setting
            retry_count: Current retry attempt
            
        Returns:
            API response dictionary
        """
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
            
            # Remove 'solidity' language identifier
            if lines and lines[0].strip().lower() == "solidity":
                lines = lines[1:]
            
            if not lines:
                continue
            
            code = '\n'.join(lines)
            
            # Add SPDX license if missing
            if not code.strip().startswith('// SPDX-License-Identifier:'):
                code = '// SPDX-License-Identifier: UNLICENSED\n' + code
            
            extracted_code.append(code)
        
        return '\n\n'.join(extracted_code) if extracted_code else text

    def compile_contract(self, sol_path: str) -> Dict[str, Any]:
        """Compile Solidity contract using solc."""
        try:
            result = subprocess.run(
                ["solc", "--gas", "--bin", sol_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            compilation_success = result.returncode == 0
            if compilation_success:
                self.statistics["successful_compilations"] += 1
            else:
                self.statistics["failed_compilations"] += 1
            
            return {
                'success': compilation_success,
                'returnCode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'returnCode': -1,
                'stdout': '',
                'stderr': 'Compilation timeout (30s)'
            }
        except Exception as e:
            return {
                'success': False,
                'returnCode': -1,
                'stdout': '',
                'stderr': str(e)
            }

    def run_slither_analysis(self, sol_path: str) -> Dict[str, Any]:
        """Run Slither security analysis on contract."""
        try:
            result = subprocess.run(
                ["slither", sol_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            return {
                'returnCode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                'returnCode': -1,
                'stdout': '',
                'stderr': 'Slither analysis timeout (60s)'
            }
        except FileNotFoundError:
            return {
                'returnCode': -1,
                'stdout': '',
                'stderr': 'Slither not found. Install with: pip install slither-analyzer'
            }
        except Exception as e:
            return {
                'returnCode': -1,
                'stdout': '',
                'stderr': str(e)
            }

    def process_prompt(self, model: str, prompt_data: Tuple[str, str, str], 
                      iteration: int, contract_dir: str) -> Dict[str, Any]:
        """Process a single prompt through the pipeline."""
        prompt_name, task, specification = prompt_data
        result = {
            "generation": {},
            "compilation": {},
            "slither": {},
            "timing": {}
        }
        
        # Build the full prompt
        full_prompt = (
            f"Generate a Solidity smart contract that satisfies the following specification. "
            f"Use Solidity ^0.8.x. Focus on correctness, security, and clarity.\n\n"
            f"Smart Contract Task: {task}\n"
            f"Specification: {specification}\n\n"
            f"Write only the solidity code."
        )
        
        # Step 1: Generate code
        generation_start = time.time()
        try:
            api_response = self.call_ollama_api(model, full_prompt)
            generation_time = time.time() - generation_start
            
            result["timing"]["generation_seconds"] = round(generation_time, 2)
            result["generation"]["response"] = api_response.get("response", "")
            result["generation"]["total_duration_ns"] = api_response.get("total_duration", 0)
            
            # Save raw response
            txt_path = os.path.join(contract_dir, f"{iteration}.txt")
            with open(txt_path, 'w', encoding="utf-8") as f:
                f.write(result["generation"]["response"])
            
            # Extract and save Solidity code
            solidity_code = self.extract_solidity_code(result["generation"]["response"])
            sol_path = os.path.join(contract_dir, f"{iteration}.sol")
            with open(sol_path, 'w', encoding="utf-8") as f:
                f.write(solidity_code)
            
            self.statistics["successful_generations"] += 1
            
        except Exception as e:
            generation_time = time.time() - generation_start
            result["timing"]["generation_seconds"] = round(generation_time, 2)
            result["generation"]["error"] = str(e)
            result["generation"]["response"] = ""
            self.statistics["failed_generations"] += 1
            return result
        
        # Step 2: Compile
        compilation_start = time.time()
        result["compilation"] = self.compile_contract(sol_path)
        result["timing"]["compilation_seconds"] = round(time.time() - compilation_start, 2)
        
        # Step 3: Slither analysis (only if compilation succeeded)
        if result["compilation"]["success"]:
            slither_start = time.time()
            result["slither"] = self.run_slither_analysis(sol_path)
            result["timing"]["slither_seconds"] = round(time.time() - slither_start, 2)
        
        result["timing"]["total_seconds"] = round(
            result["timing"]["generation_seconds"] + 
            result["timing"].get("compilation_seconds", 0) +
            result["timing"].get("slither_seconds", 0), 2
        )
        
        return result

    def run_benchmark(self, dataset_path: str = "prompts_2nd.csv") -> None:
        """Main benchmark execution."""
        print("=" * 80)
        print(" " * 25 + "LLM SOLIDITY BENCHMARK")
        print("=" * 80 + "\n")
        
        start_time = time.time()
        
        # Setup
        self.clean_repository()
        dataset = self.load_dataset(dataset_path)
        
        print(f"[MODELS] {MODELS}")
        print(f"[CONFIG] Iterations per prompt: {NUM_ITERATIONS}")
        print(f"[CONFIG] LLM timeout: {OLLAMA_TIMEOUT}s ({OLLAMA_TIMEOUT//60} minutes)")
        print(f"[CONFIG] Max retries: {MAX_RETRIES}\n")
        
        # Process each model
        for model in MODELS:
            model_start = time.time()
            model_dir = self.sanitize_filename(model)
            model_output_dir = os.path.join(self.output_dir, model_dir)
            os.makedirs(model_output_dir, exist_ok=True)
            
            print(f"\n{'='*80}")
            print(f"[MODEL] Processing: {model}")
            print(f"{'='*80}\n")
            
            self.results[model] = {}
            total_contracts = 0
            
            with yaspin(text="Initializing...") as spinner:
                # Process each prompt
                for prompt_idx, prompt_data in enumerate(dataset, 1):
                    prompt_name = prompt_data[0]
                    contract_dir = os.path.join(model_output_dir, self.sanitize_filename(prompt_name))
                    os.makedirs(contract_dir, exist_ok=True)
                    
                    self.results[model][prompt_name] = {}
                    
                    # Process iterations
                    for iteration in range(NUM_ITERATIONS):
                        iteration_num = iteration + 1
                        spinner.text = (
                            f"[{prompt_idx}/{len(dataset)}] {prompt_name} "
                            f"| Iteration {iteration_num}/{NUM_ITERATIONS}"
                        )
                        
                        iteration_start = time.time()
                        
                        try:
                            result = self.process_prompt(
                                model, prompt_data, iteration, contract_dir
                            )
                            self.results[model][prompt_name][iteration] = result
                            
                            iteration_time = time.time() - iteration_start
                            status = "✓" if result.get("compilation", {}).get("success") else "✗"
                            
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
                            self.results[model][prompt_name][iteration] = error_result
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
        
        # Print summary
        total_time = time.time() - start_time
        self.statistics["total_time"] = round(total_time, 2)
        self.print_summary()
        
        # Save results
        self.save_results()

    def save_results(self) -> None:
        """Save results to JSON file."""
        results_path = os.path.join(self.output_dir, "benchmark_results.json")
        summary_path = os.path.join(self.output_dir, "summary.json")
        
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "statistics": self.statistics,
                "configuration": {
                    "models": MODELS,
                    "iterations": NUM_ITERATIONS,
                    "timeout": OLLAMA_TIMEOUT
                }
            }, f, indent=2)
        
        print(f"\n[SAVED] Results: {results_path}")
        print(f"[SAVED] Summary: {summary_path}")

    def print_summary(self) -> None:
        """Print benchmark summary statistics."""
        print("\n" + "=" * 80)
        print(" " * 30 + "SUMMARY")
        print("=" * 80)
        print(f"\n[STATISTICS]")
        print(f"  Total prompts:              {self.statistics['total_prompts']}")
        print(f"  Successful generations:     {self.statistics['successful_generations']}")
        print(f"  Failed generations:         {self.statistics['failed_generations']}")
        print(f"  Successful compilations:    {self.statistics['successful_compilations']}")
        print(f"  Failed compilations:        {self.statistics['failed_compilations']}")
        
        if self.statistics['successful_generations'] > 0:
            success_rate = (self.statistics['successful_compilations'] / 
                          self.statistics['successful_generations'] * 100)
            print(f"  Compilation success rate:   {success_rate:.1f}%")
        
        print(f"\n[TIMING]")
        print(f"  Total execution time:       {self.statistics['total_time']:.1f}s")
        print(f"                              ({self.statistics['total_time']/60:.1f} minutes)")
        
        if self.statistics['model_times']:
            print(f"\n[MODEL TIMES]")
            for model, times in self.statistics['model_times'].items():
                print(f"  {model:25} {times['seconds']:.1f}s ({times['minutes']:.1f} min)")
        
        print("=" * 80 + "\n")


if __name__ == '__main__':
    benchmark = SolidityBenchmark()
    try:
        benchmark.run_benchmark("prompts_2nd.csv")
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Benchmark stopped by user")
    except Exception as e:
        print(f"\n\n[ERROR] Benchmark failed: {e}")
        traceback.print_exc()