import json
import os
import re
import subprocess
import time
import traceback
from typing import Dict, List, Tuple, Any
from collections import defaultdict
from datetime import datetime
from yaspin import yaspin

# Vulnerability severity mapping from Slither documentation
VULNERABILITY_SEVERITY = {
    # High Severity
    "storage-abiencoderv2-array": "High",
    "arbitrary-from-in-transferfrom": "High",
    "modifying-storage-array-by-value": "High",
    "abi-encodePacked-collision": "High",
    "incorrect-shift-in-assembly": "High",
    "multiple-constructor-schemes": "High",
    "name-reused": "High",
    "protected-variables": "High",
    "public-mappings-with-nested-variables": "High",
    "right-to-left-override-character": "High",
    "state-variable-shadowing": "High",
    "suicidal": "High",
    "uninitialized-state-variables": "High",
    "uninitialized-storage-variables": "High",
    "unprotected-upgradeable-contract": "High",
    "codex": "High",
    "arbitrary-from-in-transferfrom-used-with-permit": "High",
    "functions-that-send-ether-to-arbitrary-destinations": "High",
    "array-length-assignment": "High",
    "controlled-delegatecall": "High",
    "payable-functions-using-delegatecall-inside-a-loop": "High",
    "incorrect-exponentiation": "High",
    "incorrect-return-in-assembly": "High",
    "msgvalue-inside-a-loop": "High",
    "reentrancy-vulnerabilities": "High",
    "return-instead-of-leave-in-assembly": "High",
    "storage-signed-integer-array": "High",
    "unchecked-transfer": "High",
    "weak-PRNG": "High",
    
    # Medium Severity
    "domain-separator-collision": "Medium",
    "dangerous-enum-conversion": "Medium",
    "incorrect-erc20-interface": "Medium",
    "incorrect-erc721-interface": "Medium",
    "dangerous-strict-equalities": "Medium",
    "contracts-that-lock-ether": "Medium",
    "deletion-on-mapping-containing-a-structure": "Medium",
    "state-variable-shadowing-from-abstract-contracts": "Medium",
    "tautological-compare": "Medium",
    "tautology-or-contradiction": "Medium",
    "write-after-write": "Medium",
    "misuse-of-a-boolean-constant": "Medium",
    "constant-functions-using-assembly-code": "Medium",
    "constant-functions-changing-the-state": "Medium",
    "divide-before-multiply": "Medium",
    "out-of-order-retryable-transactions": "Medium",
    "reentrancy-vulnerabilities-1": "Medium",
    "reused-base-constructors": "Medium",
    "dangerous-usage-of-txorigin": "Medium",
    "unchecked-low-level-calls": "Medium",
    "unchecked-send": "Medium",
    "uninitialized-local-variables": "Medium",
    "unused-return": "Medium",
    
    # Low Severity
    "incorrect-modifier": "Low",
    "builtin-symbol-shadowing": "Low",
    "local-variable-shadowing": "Low",
    "uninitialized-function-pointers-in-constructors": "Low",
    "pre-declaration-usage-of-local-variables": "Low",
    "void-constructor": "Low",
    "calls-inside-a-loop": "Low",
    "missing-events-access-control": "Low",
    "missing-events-arithmetic": "Low",
    "dangerous-unary-expressions": "Low",
    "missing-zero-address-validation": "Low",
    "reentrancy-vulnerabilities-2": "Low",
    "reentrancy-vulnerabilities-3": "Low",
    "return-bomb": "Low",
    "block-timestamp": "Low",
    
    # Informational
    "assembly-usage": "Informational",
    "assert-state-change": "Informational",
    "boolean-equality": "Informational",
    "cyclomatic-complexity": "Informational",
    "deprecated-standards": "Informational",
    "unindexed-erc20-event-parameters": "Informational",
    "function-initializing-state": "Informational",
    "incorrect-using-for-usage": "Informational",
    "low-level-calls": "Informational",
    "missing-inheritance": "Informational",
    "conformance-to-solidity-naming-conventions": "Informational",
    "different-pragma-directives-are-used": "Informational",
    "redundant-statements": "Informational",
    "incorrect-versions-of-solidity": "Informational",
    "unimplemented-functions": "Informational",
    "unused-imports": "Informational",
    "unused-state-variable": "Informational",
    "costly-operations-inside-a-loop": "Informational",
    "dead-code": "Informational",
    "reentrancy-vulnerabilities-4": "Informational",
    "too-many-digits": "Informational",
    
    # Optimization
    "cache-array-length": "Optimization",
    "state-variables-that-could-be-declared-constant": "Optimization",
    "public-function-that-could-be-declared-external": "Optimization",
    "state-variables-that-could-be-declared-immutable": "Optimization",
    "public-variable-read-in-external-context": "Optimization",
}

SEVERITY_ORDER = ["High", "Medium", "Low", "Informational", "Optimization"]
MALIGN_SEVERITIES = ["High", "Medium", "Low"]


class CompilerAndAnalyzer:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        self.generation_results_path = os.path.join(output_dir, "generation_results.json")
        self.generation_summary_path = os.path.join(output_dir, "generation_summary.json")
        self.generation_results = {}
        self.folder_mapping = {}
        self.compilation_results = {}
        self.analysis_statistics = {}
        self.vulnerability_details = defaultdict(lambda: defaultdict(int))
        self.statistics = {
            "successful_compilations": 0,
            "failed_compilations": 0,
            "contracts_analyzed": 0
        }

    def sanitize_filename(self, name: str) -> str:
        """Remove invalid characters for Windows file paths."""
        return re.sub(r'[<>:"/\\|?*]', '_', name)

    def load_generation_results(self) -> None:
        """Load generation results and folder mapping from JSON files."""
        if not os.path.exists(self.generation_results_path):
            raise FileNotFoundError(f"Generation results file not found: {self.generation_results_path}")
        
        if not os.path.exists(self.generation_summary_path):
            raise FileNotFoundError(f"Generation summary file not found: {self.generation_summary_path}")
        
        with open(self.generation_results_path, 'r', encoding='utf-8') as f:
            self.generation_results = json.load(f)
        
        with open(self.generation_summary_path, 'r', encoding='utf-8') as f:
            summary = json.load(f)
            self.folder_mapping = summary.get("folder_mapping", {})
        
        print(f"[LOADED] {self.generation_results_path}")
        print(f"[LOADED] {self.generation_summary_path}")
        print(f"[MODELS] {len(self.generation_results)} model(s) found\n")

    def compile_contract(self, sol_path: str) -> Dict[str, Any]:
        """Compile Solidity contract using solc with OpenZeppelin support."""
        try:
            # Use relative path for node_modules
            cmd = [
                "solc",
                "--gas",
                "--bin",
                "--base-path", ".",
                "--include-path", "node_modules",
                "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
                sol_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.getcwd()  # Ensure we're in the project root
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
            self.statistics["failed_compilations"] += 1
            return {
                'success': False,
                'returnCode': -1,
                'stdout': '',
                'stderr': 'Compilation timeout (30s)'
            }
        except Exception as e:
            self.statistics["failed_compilations"] += 1
            return {
                'success': False,
                'returnCode': -1,
                'stdout': '',
                'stderr': f'Compilation error: {str(e)}'
            }

    def run_slither_analysis(self, sol_path: str) -> Dict[str, Any]:
        """Run Slither security analysis on contract with OpenZeppelin support."""
        try:
            # Build slither command with OpenZeppelin remappings using relative paths
            cmd = [
                "slither",
                sol_path,
                "--solc-remaps",
                "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
                "--solc-args",
                "--base-path . --include-path node_modules"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=os.getcwd()  # Ensure we're in the project root
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

    def compile_and_analyze_all(self) -> None:
        """Compile and analyze all generated contracts."""
        print("=" * 80)
        print(" " * 20 + "COMPILATION AND ANALYSIS")
        print("=" * 80 + "\n")
        
        for model_name, model_data in self.generation_results.items():
            print(f"\n{'='*80}")
            print(f"[MODEL] Processing: {model_name}")
            print(f"{'='*80}\n")
            
            self.compilation_results[model_name] = {}
            total_contracts = 0
            
            with yaspin(text="Initializing...") as spinner:
                for prompt_name, iterations in model_data.items():
                    self.compilation_results[model_name][prompt_name] = {}
                    
                    for iteration_key, iteration_data in iterations.items():
                        total_contracts += 1
                        spinner.text = f"Processing {prompt_name} - {iteration_key}"
                        
                        result = {
                            "generation": iteration_data,
                            "compilation": {},
                            "slither": {},
                            "timing": {}
                        }
                        
                        # Skip if generation failed
                        if iteration_data.get("error"):
                            result["compilation"]["success"] = False
                            result["compilation"]["error"] = "Generation failed"
                            self.compilation_results[model_name][prompt_name][iteration_key] = result
                            spinner.write(f"  ✗ {prompt_name} [{iteration_key}] - Generation failed")
                            continue
                        
                        # Get actual folder names from mapping
                        iteration_number = iteration_key.replace("iteration_", "")
                        
                        if model_name in self.folder_mapping:
                            model_folder = self.folder_mapping[model_name]["folder_name"]
                            prompt_mapping = self.folder_mapping[model_name]["prompts"].get(prompt_name, {})
                            prompt_folder = prompt_mapping.get("folder_name", self.sanitize_filename(prompt_name))
                        else:
                            model_folder = self.sanitize_filename(model_name)
                            prompt_folder = self.sanitize_filename(prompt_name)
                        
                        sol_path = os.path.join(self.output_dir, model_folder, prompt_folder, f"{iteration_number}.sol")
                        
                        if not os.path.exists(sol_path):
                            result["compilation"]["success"] = False
                            result["compilation"]["error"] = f"Sol file not found: {sol_path}"
                            self.compilation_results[model_name][prompt_name][iteration_key] = result
                            spinner.write(f"  ✗ {prompt_name} [{iteration_key}] - Sol file not found")
                            continue
                        
                        # Compile
                        comp_start = time.time()
                        result["compilation"] = self.compile_contract(sol_path)
                        result["timing"]["compilation_seconds"] = round(time.time() - comp_start, 2)
                        
                        # Run Slither if compilation succeeded
                        if result["compilation"]["success"]:
                            slither_start = time.time()
                            result["slither"] = self.run_slither_analysis(sol_path)
                            result["timing"]["slither_seconds"] = round(time.time() - slither_start, 2)
                            self.statistics["contracts_analyzed"] += 1
                            status = "✓"
                        else:
                            status = "✗"
                        
                        result["timing"]["total_seconds"] = round(
                            result["timing"].get("compilation_seconds", 0) +
                            result["timing"].get("slither_seconds", 0), 2
                        )
                        
                        self.compilation_results[model_name][prompt_name][iteration_key] = result
                        
                        spinner.write(
                            f"  {status} {prompt_name} [{iteration_key}] - "
                            f"Compile: {result['timing'].get('compilation_seconds', 0):.1f}s"
                        )
                
                spinner.ok(f"✓ Completed {total_contracts} contracts for {model_name}")

    def extract_vulnerabilities(self, slither_stderr: str) -> List[str]:
        """Extract vulnerability types from Slither output."""
        vulnerabilities = []
        base_url = "https://github.com/crytic/slither/wiki/detector-documentation#"
        
        stderr_lower = slither_stderr.lower()
        
        for vuln_type in VULNERABILITY_SEVERITY.keys():
            vuln_url = f"{base_url}{vuln_type}\n"
            count = stderr_lower.count(vuln_url.lower())
            if count > 0:
                vulnerabilities.extend([vuln_type] * count)
        
        return vulnerabilities

    def has_only_benign_vulnerabilities(self, vulnerabilities: List[str]) -> bool:
        """Check if contract only has Optimization/Informational issues."""
        for vuln in vulnerabilities:
            severity = VULNERABILITY_SEVERITY.get(vuln, "Unknown")
            if severity not in ["Optimization", "Informational"]:
                return False
        return True

    def initialize_severity_dict(self) -> Dict[str, int]:
        """Create a dictionary with all severity levels initialized to 0."""
        return {severity: 0 for severity in SEVERITY_ORDER}

    def analyze_results(self) -> None:
        """Perform statistical analysis on compilation and slither results."""
        print("\n" + "=" * 80)
        print(" " * 25 + "ANALYZING RESULTS")
        print("=" * 80 + "\n")
        
        for model_name, model_data in self.compilation_results.items():
            print(f"[ANALYZING] {model_name}...")
            
            model_stats = {
                "compilation": {
                    "successful": 0,
                    "failed": 0,
                    "success_rate": 0.0
                },
                "generation": {
                    "successful": 0,
                    "failed": 0,
                    "success_rate": 0.0
                },
                "vulnerabilities": self.initialize_severity_dict(),
                "clean_contracts": 0,
                "contracts_analyzed": 0,
                "timing": {
                    "total_generation_time": 0.0,
                    "avg_generation_time": 0.0,
                    "total_compilation_time": 0.0,
                    "avg_compilation_time": 0.0,
                    "total_slither_time": 0.0,
                    "avg_slither_time": 0.0
                },
                "prompt_details": {}
            }
            
            for prompt_name, iterations in model_data.items():
                prompt_stats = {
                    "compilation": {
                        "successful": 0,
                        "failed": 0,
                        "success_rate": 0.0
                    },
                    "vulnerabilities": self.initialize_severity_dict(),
                    "clean_contracts": 0,
                    "timing": {
                        "total_generation_time": 0.0,
                        "avg_generation_time": 0.0
                    }
                }
                
                for iteration_key, iteration_data in iterations.items():
                    generation = iteration_data.get("generation", {})
                    
                    # Check generation success
                    if generation.get("error"):
                        model_stats["generation"]["failed"] += 1
                        prompt_stats["compilation"]["failed"] += 1
                        continue
                    
                    model_stats["generation"]["successful"] += 1
                    
                    # Track timing
                    gen_time = generation.get("timing", {}).get("generation_seconds", 0)
                    comp_time = iteration_data.get("timing", {}).get("compilation_seconds", 0)
                    slither_time = iteration_data.get("timing", {}).get("slither_seconds", 0)
                    
                    model_stats["timing"]["total_generation_time"] += gen_time
                    model_stats["timing"]["total_compilation_time"] += comp_time
                    model_stats["timing"]["total_slither_time"] += slither_time
                    prompt_stats["timing"]["total_generation_time"] += gen_time
                    
                    # Check compilation
                    compilation = iteration_data.get("compilation", {})
                    if compilation.get("success"):
                        model_stats["compilation"]["successful"] += 1
                        prompt_stats["compilation"]["successful"] += 1
                        model_stats["contracts_analyzed"] += 1
                        
                        # Analyze vulnerabilities
                        slither_data = iteration_data.get("slither", {})
                        slither_stderr = slither_data.get("stderr", "")
                        
                        vulnerabilities = self.extract_vulnerabilities(slither_stderr)
                        
                        # Count vulnerabilities by severity
                        for vuln in vulnerabilities:
                            severity = VULNERABILITY_SEVERITY.get(vuln, "Unknown")
                            if severity in model_stats["vulnerabilities"]:
                                model_stats["vulnerabilities"][severity] += 1
                                prompt_stats["vulnerabilities"][severity] += 1
                                self.vulnerability_details[model_name][vuln] += 1
                        
                        # Check if contract is "clean"
                        if self.has_only_benign_vulnerabilities(vulnerabilities):
                            model_stats["clean_contracts"] += 1
                            prompt_stats["clean_contracts"] += 1
                    else:
                        model_stats["compilation"]["failed"] += 1
                        prompt_stats["compilation"]["failed"] += 1
                
                # Calculate prompt-level statistics
                total_prompt_attempts = prompt_stats["compilation"]["successful"] + prompt_stats["compilation"]["failed"]
                if total_prompt_attempts > 0:
                    prompt_stats["compilation"]["success_rate"] = round(
                        (prompt_stats["compilation"]["successful"] / total_prompt_attempts) * 100, 2
                    )
                    prompt_stats["timing"]["avg_generation_time"] = round(
                        prompt_stats["timing"]["total_generation_time"] / total_prompt_attempts, 2
                    )
                
                model_stats["prompt_details"][prompt_name] = prompt_stats
            
            # Calculate model-level statistics
            total_attempts = model_stats["compilation"]["successful"] + model_stats["compilation"]["failed"]
            total_gen_attempts = model_stats["generation"]["successful"] + model_stats["generation"]["failed"]
            
            if total_attempts > 0:
                model_stats["compilation"]["success_rate"] = round(
                    (model_stats["compilation"]["successful"] / total_attempts) * 100, 2
                )
            
            if total_gen_attempts > 0:
                model_stats["generation"]["success_rate"] = round(
                    (model_stats["generation"]["successful"] / total_gen_attempts) * 100, 2
                )
                model_stats["timing"]["avg_generation_time"] = round(
                    model_stats["timing"]["total_generation_time"] / total_gen_attempts, 2
                )
            
            if model_stats["compilation"]["successful"] > 0:
                model_stats["timing"]["avg_compilation_time"] = round(
                    model_stats["timing"]["total_compilation_time"] / model_stats["compilation"]["successful"], 2
                )
            
            if model_stats["contracts_analyzed"] > 0:
                model_stats["timing"]["avg_slither_time"] = round(
                    model_stats["timing"]["total_slither_time"] / model_stats["contracts_analyzed"], 2
                )
            
            self.analysis_statistics[model_name] = model_stats
        
        print("\n[COMPLETED] Analysis finished\n")

    def get_top_vulnerabilities(self, model_name: str, top_n: int = 10, malign_only: bool = False) -> List[Tuple[str, int]]:
        """Get the most common vulnerabilities for a model."""
        vuln_counts = self.vulnerability_details.get(model_name, {})
        
        if malign_only:
            vuln_counts = {k: v for k, v in vuln_counts.items() 
                          if VULNERABILITY_SEVERITY.get(k, "Unknown") in MALIGN_SEVERITIES}
        
        return sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def save_results(self) -> None:
        """Save all results to JSON files."""
        compilation_path = os.path.join(self.output_dir, "compilation_results.json")
        with open(compilation_path, 'w', encoding='utf-8') as f:
            json.dump(self.compilation_results, f, indent=2)
        print(f"[SAVED] Compilation results: {compilation_path}")
        
        analysis_path = os.path.join(self.output_dir, "final_analysis.json")
        with open(analysis_path, 'w', encoding='utf-8') as f:
            json.dump({
                "analysis_timestamp": datetime.now().isoformat(),
                "statistics": self.analysis_statistics,
                "vulnerability_details": dict(self.vulnerability_details),
                "compilation_statistics": self.statistics
            }, f, indent=2)
        print(f"[SAVED] Final analysis: {analysis_path}")

    def generate_summary_report(self) -> None:
        """Generate human-readable summary reports."""
        detailed_path = os.path.join(self.output_dir, "detailed_summary.txt")
        with open(detailed_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + "FINAL ANALYSIS SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Generation Results: {self.generation_results_path}\n\n")
            
            for model_name, stats in self.analysis_statistics.items():
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"MODEL: {model_name}\n")
                f.write("=" * 80 + "\n\n")
                
                # Generation Statistics
                f.write("GENERATION STATISTICS:\n")
                f.write("-" * 40 + "\n")
                total_gen = stats["generation"]["successful"] + stats["generation"]["failed"]
                f.write(f"  Total Attempts:        {total_gen}\n")
                f.write(f"  Successful:            {stats['generation']['successful']}\n")
                f.write(f"  Failed:                {stats['generation']['failed']}\n")
                f.write(f"  Success Rate:          {stats['generation']['success_rate']:.2f}%\n")
                f.write(f"  Avg Generation Time:   {stats['timing']['avg_generation_time']:.2f}s\n\n")
                
                # Compilation Statistics
                f.write("COMPILATION STATISTICS:\n")
                f.write("-" * 40 + "\n")
                total_comp = stats["compilation"]["successful"] + stats["compilation"]["failed"]
                f.write(f"  Total Attempts:        {total_comp}\n")
                f.write(f"  Successful:            {stats['compilation']['successful']}\n")
                f.write(f"  Failed:                {stats['compilation']['failed']}\n")
                f.write(f"  Success Rate:          {stats['compilation']['success_rate']:.2f}%\n")
                f.write(f"  Avg Compilation Time:  {stats['timing']['avg_compilation_time']:.2f}s\n\n")
                
                # Security Analysis
                f.write("SECURITY ANALYSIS:\n")
                f.write("-" * 40 + "\n")
                f.write(f"  Contracts Analyzed:    {stats['contracts_analyzed']}\n")
                f.write(f"  Clean Contracts:       {stats['clean_contracts']}\n")
                
                if stats['contracts_analyzed'] > 0:
                    clean_rate = (stats['clean_contracts'] / stats['contracts_analyzed']) * 100
                    f.write(f"  Clean Rate:            {clean_rate:.2f}%\n\n")
                else:
                    f.write(f"  Clean Rate:            N/A\n\n")
                
                # Malign Vulnerability Breakdown
                f.write("MALIGN VULNERABILITY BREAKDOWN:\n")
                f.write("-" * 40 + "\n")
                malign_vulns_count = sum(stats["vulnerabilities"][sev] for sev in MALIGN_SEVERITIES)
                f.write(f"  Total Malign Vulnerabilities: {malign_vulns_count}\n\n")
                
                for severity in MALIGN_SEVERITIES:
                    count = stats["vulnerabilities"][severity]
                    if malign_vulns_count > 0:
                        percentage = (count / malign_vulns_count) * 100
                        f.write(f"  {severity:15} {count:6} ({percentage:5.2f}%)\n")
                    else:
                        f.write(f"  {severity:15} {count:6}\n")
                
                # Top Malign Vulnerabilities
                f.write("\n\nTOP 10 MOST COMMON MALIGN VULNERABILITIES:\n")
                f.write("-" * 40 + "\n")
                top_vulns = self.get_top_vulnerabilities(model_name, 10, malign_only=True)
                
                if top_vulns:
                    for i, (vuln_type, count) in enumerate(top_vulns, 1):
                        severity = VULNERABILITY_SEVERITY.get(vuln_type, "Unknown")
                        f.write(f"  {i:2}. {vuln_type:50} [{severity:13}] x{count}\n")
                else:
                    f.write("  No malign vulnerabilities detected\n")
                
                # Per-Prompt Summary
                f.write("\n\nPER-PROMPT SUMMARY (MALIGN VULNERABILITIES):\n")
                f.write("-" * 40 + "\n")
                
                for prompt_name, prompt_stats in stats["prompt_details"].items():
                    malign_vulns_prompt = sum(prompt_stats["vulnerabilities"][sev] for sev in MALIGN_SEVERITIES)
                    f.write(f"\n  {prompt_name}:\n")
                    f.write(f"    Compilation Success: {prompt_stats['compilation']['successful']}/")
                    f.write(f"{prompt_stats['compilation']['successful'] + prompt_stats['compilation']['failed']}")
                    f.write(f" ({prompt_stats['compilation']['success_rate']:.1f}%)\n")
                    f.write(f"    Clean Contracts:     {prompt_stats['clean_contracts']}\n")
                    f.write(f"    Malign Vulnerabilities: {malign_vulns_prompt}\n")
                    
                    for severity in MALIGN_SEVERITIES:
                        count = prompt_stats["vulnerabilities"][severity]
                        if count > 0:
                            f.write(f"      - {severity}: {count}\n")
                    
                    f.write(f"    Avg Gen Time:        {prompt_stats['timing']['avg_generation_time']:.2f}s\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("NOTE: This report excludes Informational and Optimization issues.\n")
            f.write("      Only security-critical vulnerabilities (High, Medium, Low) are included.\n")
            f.write("=" * 80 + "\n")
        
        print(f"[SAVED] Detailed summary: {detailed_path}")
        
        # Quick summary
        quick_path = os.path.join(self.output_dir, "quick_summary.txt")
        with open(quick_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + " QUICK SUMMARY\n")
            f.write("=" * 80 + "\n")
            
            for model_name, stats in self.analysis_statistics.items():
                f.write(f"\n[{model_name}]\n")
                f.write(f"  Avg Generation Time: {stats['timing']['avg_generation_time']:.2f}s\n")
                total_comp = stats['compilation']['successful'] + stats['compilation']['failed']
                f.write(f"  Compilation Rate:    {stats['compilation']['successful']}/{total_comp}")
                f.write(f" ({stats['compilation']['success_rate']:.2f}%)\n")
                f.write(f"  Clean Contracts:     {stats['clean_contracts']}/{stats['contracts_analyzed']}\n")
                
                malign_vulns = sum(stats["vulnerabilities"][sev] for sev in MALIGN_SEVERITIES)
                f.write(f"  Vulnerabilities:     {malign_vulns}\n")
                f.write(f"    High:              {stats['vulnerabilities']['High']}\n")
                f.write(f"    Medium:            {stats['vulnerabilities']['Medium']}\n")
                f.write(f"    Low:               {stats['vulnerabilities']['Low']}\n")
        
        print(f"[SAVED] Quick summary: {quick_path}")
        
        # Print quick summary to console
        print("\n" + "=" * 80)
        with open(quick_path, 'r', encoding='utf-8') as f:
            print(f.read())
        print("=" * 80 + "\n")


def main():
    analyzer = CompilerAndAnalyzer("output")
    
    try:
        analyzer.load_generation_results()
        analyzer.compile_and_analyze_all()
        analyzer.analyze_results()
        analyzer.save_results()
        analyzer.generate_summary_report()
        
        print("=" * 80)
        print("[SUCCESS] Compilation and analysis complete!")
        print("=" * 80)
        
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        print("Please run generate_contracts.py first to generate contracts.")
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    main()