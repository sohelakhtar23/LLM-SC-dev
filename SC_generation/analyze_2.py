import json
import os
from typing import Dict, List, Tuple, Any
from collections import Counter, defaultdict
from datetime import datetime

# Vulnerability severity mapping from Slither documentation
# Source: https://github.com/crytic/slither/wiki/Detector-Documentation
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
MALIGN_SEVERITIES = ["High", "Medium", "Low"]  # Only security-critical vulnerabilities


class SlitherAnalyzer:
    def __init__(self, results_path: str = "output/benchmark_results.json"):
        self.results_path = results_path
        self.results = {}
        self.statistics = {}
        self.vulnerability_details = defaultdict(lambda: defaultdict(int))
        
    def load_results(self) -> None:
        """Load benchmark results from JSON file."""
        if not os.path.exists(self.results_path):
            raise FileNotFoundError(f"Results file not found: {self.results_path}")
        
        with open(self.results_path, 'r', encoding='utf-8') as f:
            self.results = json.load(f)
        
        print(f"[LOADED] {self.results_path}")
        print(f"[MODELS] {len(self.results)} model(s) found\n")
    
    def has_only_benign_vulnerabilities(self, vulnerabilities: List[str]) -> bool:
        """Check if contract only has Optimization/Informational issues."""
        for vuln in vulnerabilities:
            severity = VULNERABILITY_SEVERITY.get(vuln, "Unknown")
            if severity not in ["Optimization", "Informational"]:
                return False
        return True
    
    def extract_vulnerabilities(self, slither_stderr: str) -> List[str]:
        """Extract vulnerability types from Slither output."""
        vulnerabilities = []
        base_url = "https://github.com/crytic/slither/wiki/detector-documentation#"
        
        # Convert to lowercase for case-insensitive matching
        stderr_lower = slither_stderr.lower()
        
        for vuln_type in VULNERABILITY_SEVERITY.keys():
            vuln_url = f"{base_url}{vuln_type}\n"
            count = stderr_lower.count(vuln_url.lower())
            if count > 0:
                vulnerabilities.extend([vuln_type] * count)
        
        return vulnerabilities
    
    def initialize_severity_dict(self) -> Dict[str, int]:
        """Create a dictionary with all severity levels initialized to 0."""
        return {severity: 0 for severity in SEVERITY_ORDER}
    
    def analyze_model(self, model_name: str, model_data: Dict) -> Dict[str, Any]:
        """Analyze results for a single model."""
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
            "clean_contracts": 0,  # Contracts with only Optimization/Informational issues
            "contracts_analyzed": 0,
            "timing": {
                "total_generation_time": 0.0,
                "avg_generation_time": 0.0,
                "total_compilation_time": 0.0,
                "avg_compilation_time": 0.0
            },
            "prompt_details": {}
        }
        
        total_contracts = 0
        
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
                total_contracts += 1
                
                # Check generation success
                if "error" in iteration_data or not iteration_data.get("generation", {}).get("response"):
                    model_stats["generation"]["failed"] += 1
                    prompt_stats["compilation"]["failed"] += 1
                    continue
                
                model_stats["generation"]["successful"] += 1
                
                # Track timing
                timing = iteration_data.get("timing", {})
                gen_time = timing.get("generation_seconds", 0)
                comp_time = timing.get("compilation_seconds", 0)
                
                model_stats["timing"]["total_generation_time"] += gen_time
                model_stats["timing"]["total_compilation_time"] += comp_time
                prompt_stats["timing"]["total_generation_time"] += gen_time
                
                # Check compilation
                compilation = iteration_data.get("compilation", {})
                if compilation.get("success") or compilation.get("returnCode") == 0:
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
                    
                    # Check if contract is "clean" (only benign issues)
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
        
        return model_stats
    
    def analyze(self) -> None:
        """Perform complete analysis of all models."""
        print("=" * 80)
        print(" " * 25 + "ANALYZING RESULTS")
        print("=" * 80 + "\n")
        
        for model_name, model_data in self.results.items():
            print(f"[ANALYZING] {model_name}...")
            self.statistics[model_name] = self.analyze_model(model_name, model_data)
        
        print("\n[COMPLETED] Analysis finished\n")
    
    def get_top_vulnerabilities(self, model_name: str, top_n: int = 10, malign_only: bool = False) -> List[Tuple[str, int]]:
        """Get the most common vulnerabilities for a model."""
        vuln_counts = self.vulnerability_details.get(model_name, {})
        
        if malign_only:
            # Filter only malign vulnerabilities
            vuln_counts = {k: v for k, v in vuln_counts.items() 
                          if VULNERABILITY_SEVERITY.get(k, "Unknown") in MALIGN_SEVERITIES}
        
        return sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    def save_results(self, output_path: str = "output/final_analysis.json") -> None:
        """Save analysis results to JSON file."""
        output_data = {
            "analysis_timestamp": datetime.now().isoformat(),
            "statistics": self.statistics,
            "vulnerability_details": dict(self.vulnerability_details)
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"[SAVED] Detailed analysis: {output_path}")
    
    def generate_summary_report(self, output_path: str) -> None:
        """Generate a human-readable summary report."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + "FINAL ANALYSIS SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Results File: {self.results_path}\n\n")
            
            for model_name, stats in self.statistics.items():
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
                
                # Vulnerability Breakdown (Malign Only)
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
                
                # Per-Prompt Summary (Malign Only)
                f.write("\n\nPER-PROMPT SUMMARY (MALIGN VULNERABILITIES):\n")
                f.write("-" * 40 + "\n")
                
                for prompt_name, prompt_stats in stats["prompt_details"].items():
                    malign_vulns_prompt = sum(prompt_stats["vulnerabilities"][sev] for sev in MALIGN_SEVERITIES)
                    f.write(f"\n  {prompt_name}:\n")
                    f.write(f"    Compilation Success: {prompt_stats['compilation']['successful']}/{prompt_stats['compilation']['successful'] + prompt_stats['compilation']['failed']}")
                    f.write(f" ({prompt_stats['compilation']['success_rate']:.1f}%)\n")
                    f.write(f"    Clean Contracts:     {prompt_stats['clean_contracts']}\n")
                    f.write(f"    Malign Vulnerabilities: {malign_vulns_prompt}\n")
                    
                    # Show breakdown by severity for this prompt
                    for severity in MALIGN_SEVERITIES:
                        count = prompt_stats["vulnerabilities"][severity]
                        if count > 0:
                            f.write(f"      - {severity}: {count}\n")
                    
                    f.write(f"    Avg Gen Time:        {prompt_stats['timing']['avg_generation_time']:.2f}s\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("NOTE: This report excludes Informational and Optimization issues.\n")
            f.write("      Only security-critical vulnerabilities (High, Medium, Low) are included.\n")
            f.write("=" * 80 + "\n")
        print(f"[SAVED] Summary report: {output_path}")


    def print_quick_summary(self, output_path: str) -> None:
        """Print a quick summary to a text file and console."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + " QUICK SUMMARY\n")
            f.write("=" * 80 + "\n")
        
            for model_name, stats in self.statistics.items():
                f.write(f"[{model_name}]\n")
                f.write(f"  Avg Generation Time: {stats['timing']['avg_generation_time']}\n")
                f.write(f"  Compilation Rate:    {stats['compilation']['successful']}/{stats['compilation']['successful'] + stats['compilation']['failed']} ({stats['compilation']['success_rate']:.2f}%)\n")
                f.write(f"  Clean Contracts:     {stats['clean_contracts']}/{stats['contracts_analyzed']}\n")

                malign_vulns = sum(stats["vulnerabilities"][sev] for sev in MALIGN_SEVERITIES)
                f.write(f"  Vulnerabilities Count: {malign_vulns}\n")
                f.write(f"    High:          {stats['vulnerabilities']['High']}\n")
                f.write(f"    Medium:        {stats['vulnerabilities']['Medium']}\n")
                f.write(f"    Low:           {stats['vulnerabilities']['Low']}\n")
                f.write("\n")
        with open(output_path, 'r', encoding='utf-8') as f:
            print(f.read())

def main():
    analyzer = SlitherAnalyzer("output/benchmark_results.json")
    
    try:
        analyzer.load_results()
        analyzer.analyze()
        analyzer.save_results("output/final_analysis.json")
        analyzer.generate_summary_report("output/detailed_summary.txt")
        analyzer.print_quick_summary("output/quick_summary.txt")
        
        print("=" * 80)
        print("[SUCCESS] Analysis complete!")
        print("=" * 80)
        
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        print("Please run the benchmark pipeline first to generate results.")
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()