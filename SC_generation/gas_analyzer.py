import os
import json
import subprocess
import time
import re
from pathlib import Path
from typing import Dict, List, Optional
from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version
import pandas as pd
from datetime import datetime


class GasConsumptionAnalyzer:
    def __init__(self, output_dir: str = "output"):
        """
        Initialize the Gas Consumption Analyzer
        
        Args:
            output_dir: Directory containing contracts and analysis results
        """
        self.output_dir = Path(output_dir)
        self.compilation_results_path = self.output_dir / "compilation_results.json"
        self.generation_summary_path = self.output_dir / "generation_summary.json"
        self.final_analysis_path = self.output_dir / "final_analysis.json"
        
        self.compilation_results = {}
        self.folder_mapping = {}
        self.gas_results = []
        
        self.anvil_process = None
        self.w3 = None
        
    def load_results(self) -> bool:
        """Load compilation results and folder mapping."""
        try:
            if not self.compilation_results_path.exists():
                print(f"[ERROR] Compilation results not found: {self.compilation_results_path}")
                print("Please run compile_and_analyze.py first.")
                return False
            
            with open(self.compilation_results_path, 'r', encoding='utf-8') as f:
                self.compilation_results = json.load(f)
            
            with open(self.generation_summary_path, 'r', encoding='utf-8') as f:
                summary = json.load(f)
                self.folder_mapping = summary.get("folder_mapping", {})
            
            print(f"[LOADED] {self.compilation_results_path}")
            print(f"[LOADED] {self.generation_summary_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to load results: {e}")
            return False
    
    def start_anvil(self, port: int = 8545) -> bool:
        """Start Anvil local network."""
        try:
            print("\n[ANVIL] Starting Anvil local blockchain...")
            self.anvil_process = subprocess.Popen(
                ["anvil", "--port", str(port), "--block-time", "1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(3)
            
            self.w3 = Web3(Web3.HTTPProvider(
                f'http://127.0.0.1:{port}',
                request_kwargs={'timeout': 60}
            ))
            
            if self.w3.is_connected():
                print(f"[ANVIL] ✓ Connected to Anvil on port {port}\n")
                return True
            else:
                print("[ANVIL] ✗ Failed to connect to Anvil")
                return False
                
        except FileNotFoundError:
            print("[ANVIL] ✗ Anvil not found. Please install Foundry: https://book.getfoundry.sh/")
            return False
        except Exception as e:
            print(f"[ANVIL] ✗ Error starting Anvil: {e}")
            return False
    
    def stop_anvil(self):
        """Stop Anvil process."""
        if self.anvil_process:
            self.anvil_process.terminate()
            self.anvil_process.wait()
            print("\n[ANVIL] ✓ Anvil stopped")
    
    def sanitize_filename(self, name: str) -> str:
        """Remove invalid characters for Windows file paths."""
        return re.sub(r'[<>:"/\\|?*]', '_', name)
    
    def compile_contract_for_deployment(self, sol_path: Path) -> Optional[Dict]:
        """
        Compile a Solidity contract for deployment with OpenZeppelin support.
        
        Args:
            sol_path: Path to the .sol file
            
        Returns:
            Compiled contract data (abi, bin) or None if compilation fails
        """
        try:
            with open(sol_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Extract pragma version
            pragma_line = [line for line in source_code.split('\n') if 'pragma solidity' in line]
            solc_version = '0.8.20'  # Default version
            
            if pragma_line:
                version_str = pragma_line[0].split('pragma solidity')[1].strip().replace(';', '')
                # Extract version number (e.g., ^0.8.0 -> 0.8.20)
                if '^0.8' in version_str or '>=0.8' in version_str:
                    solc_version = '0.8.20'
                elif '^0.7' in version_str or '>=0.7' in version_str:
                    solc_version = '0.7.6'
            
            # Install and set solc version
            try:
                install_solc(solc_version)
                set_solc_version(solc_version)
            except:
                pass
            
            # Set up import remappings for OpenZeppelin
            import_remappings = [
                "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
                "openzeppelin-solidity/contracts/=node_modules/openzeppelin-solidity/contracts/",
                "@openzeppelin-contracts/=node_modules/@openzeppelin/contracts/",
            ]
            
            # Compile with import remappings
            compiled = compile_source(
                source_code,
                output_values=['abi', 'bin'],
                solc_version=solc_version,
                import_remappings=import_remappings,
                base_path=str(Path.cwd()),
                allow_paths=[str(Path.cwd()), str(Path.cwd() / "node_modules")]
            )
            
            # Get the first contract
            contract_id = list(compiled.keys())[0]
            return compiled[contract_id]
            
        except Exception as e:
            print(f"    ✗ Compilation for deployment failed: {str(e)[:100]}")
            return None
    
    def generate_constructor_args(self, abi: List[Dict]) -> List:
        """
        Generate default constructor arguments based on ABI parameter types
        
        Args:
            abi: Contract ABI
            
        Returns:
            List of constructor arguments
        """
        # Find constructor in ABI
        constructor = None
        for item in abi:
            if item.get('type') == 'constructor':
                constructor = item
                break
        
        if not constructor or not constructor.get('inputs'):
            return []
        
        args = []
        account = self.w3.eth.accounts[0]
        
        for param in constructor['inputs']:
            param_type = param['type']
            
            # Handle different parameter types
            if param_type == 'address':
                args.append(account)
            elif param_type.startswith('uint'):
                # Use reasonable default values
                args.append(1000000)  # 1 million for token supply, etc.
            elif param_type.startswith('int'):
                args.append(100)
            elif param_type == 'string':
                args.append(f"Default_{param['name']}")
            elif param_type == 'bool':
                args.append(True)
            elif param_type == 'bytes32':
                args.append(b'0' * 32)
            elif param_type.startswith('bytes'):
                args.append(b'')
            elif param_type.endswith('[]'):
                # Empty array for dynamic arrays
                args.append([])
            elif '[' in param_type:
                # Fixed size array
                size = int(param_type.split('[')[1].split(']')[0])
                base_type = param_type.split('[')[0]
                if base_type == 'address':
                    args.append([account] * size)
                elif base_type.startswith('uint'):
                    args.append([0] * size)
                else:
                    args.append([0] * size)
            else:
                # Default to 0 for unknown types
                args.append(0)
        
        return args
    
    def deploy_and_measure_gas(self, contract_data: Dict, contract_name: str) -> Optional[int]:
        """
        Deploy contract to Anvil and measure gas consumption
        Skip if deployment takes too long
        
        Args:
            contract_data: Compiled contract data (abi, bin)
            contract_name: Name of the contract
            
        Returns:
            Gas used for deployment or None if deployment fails/times out
        """
        try:
            # Get default account
            account = self.w3.eth.accounts[0]
            
            # Create contract instance
            Contract = self.w3.eth.contract(
                abi=contract_data['abi'],
                bytecode=contract_data['bin']
            )
            
            # Generate constructor arguments
            constructor_args = self.generate_constructor_args(contract_data['abi'])
            
            if constructor_args:
                print(f"  ℹ Constructor args: {constructor_args}")
            
            # Deploy contract with or without constructor arguments
            tx_params = {
                'from': account,
                'gas': 10000000  # 10M gas limit
            }
            
            if constructor_args:
                tx_hash = Contract.constructor(*constructor_args).transact(tx_params)
            else:
                tx_hash = Contract.constructor().transact(tx_params)
            
            # Wait for transaction receipt with SHORT timeout (30 seconds max)
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
            
            gas_used = tx_receipt['gasUsed']
            print(f"  ✓ Deployed successfully - Gas used: {gas_used:,}")
            
            return gas_used
            
        except Exception as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                print(f"  ⏩ Skipped (timeout) - Moving to next file")
            else:
                print(f"  ⏩ Skipped (error) - {error_msg[:80]}...")
            
            return None
    
    def analyze_gas_consumption(self):
        """Analyze gas consumption for all successfully compiled contracts."""
        print("=" * 80)
        print(" " * 25 + "GAS CONSUMPTION ANALYSIS")
        print("=" * 80 + "\n")
        
        if not self.load_results():
            return
        
        if not self.start_anvil():
            return
        
        try:
            total_processed = 0
            total_deployable = 0
            
            for model_name, model_data in self.compilation_results.items():
                print(f"\n{'='*80}")
                print(f"[MODEL] Processing: {model_name}")
                print(f"{'='*80}\n")
                
                for prompt_name, iterations in model_data.items():
                    print(f"  [CONTRACT TYPE] {prompt_name}")
                    
                    for iteration_key, iteration_data in iterations.items():
                        compilation = iteration_data.get("compilation", {})
                        
                        # Skip if compilation failed
                        if not compilation.get("success"):
                            continue
                        
                        # Get the .sol file path
                        iteration_number = iteration_key.replace("iteration_", "")
                        
                        if model_name in self.folder_mapping:
                            model_folder = self.folder_mapping[model_name]["folder_name"]
                            prompt_mapping = self.folder_mapping[model_name]["prompts"].get(prompt_name, {})
                            prompt_folder = prompt_mapping.get("folder_name", self.sanitize_filename(prompt_name))
                        else:
                            model_folder = self.sanitize_filename(model_name)
                            prompt_folder = self.sanitize_filename(prompt_name)
                        
                        sol_path = self.output_dir / model_folder / prompt_folder / f"{iteration_number}.sol"
                        
                        print(f"    [{iteration_key}] {sol_path.name}")
                        total_processed += 1
                        
                        # Compile for deployment (py-solc-x compilation)
                        compiled = self.compile_contract_for_deployment(sol_path)
                        if not compiled:
                            self.gas_results.append({
                                'model': model_name,
                                'contract_type': prompt_name,
                                'file_name': sol_path.name,
                                'iteration': iteration_key,
                                'compilation_success': True,
                                'deployment_compilation_success': False,
                                'deployment_success': False,
                                'gas_used': None
                            })
                            continue
                        
                        # Deploy and measure gas
                        gas_used = self.deploy_and_measure_gas(compiled, sol_path.stem)
                        
                        if gas_used is not None:
                            total_deployable += 1
                        
                        self.gas_results.append({
                            'model': model_name,
                            'contract_type': prompt_name,
                            'file_name': sol_path.name,
                            'iteration': iteration_key,
                            'compilation_success': True,
                            'deployment_compilation_success': True,
                            'deployment_success': gas_used is not None,
                            'gas_used': gas_used
                        })
            
            print(f"\n{'='*80}")
            print(f"[SUMMARY] Processed: {total_processed} | Deployable: {total_deployable}")
            print(f"{'='*80}\n")
            
            self.save_results()
            
        finally:
            self.stop_anvil()
    
    def save_results(self):
        """Save gas consumption results to CSV and JSON."""
        # Save CSV
        csv_path = self.output_dir / "gas_consumption_results.csv"
        df = pd.DataFrame(self.gas_results)
        df.to_csv(csv_path, index=False)
        print(f"[SAVED] Gas consumption CSV: {csv_path}")
        
        # Save JSON with statistics
        gas_json_path = self.output_dir / "gas_consumption_analysis.json"
        
        statistics = {}
        for model in df['model'].unique():
            model_data = df[df['model'] == model]
            deployable = model_data[model_data['deployment_success'] == True]
            
            statistics[model] = {
                "total_contracts": len(model_data),
                "deployment_compilation_success": int(model_data['deployment_compilation_success'].sum()),
                "deployment_success": int(model_data['deployment_success'].sum()),
                "deployment_success_rate": round(model_data['deployment_success'].mean() * 100, 2),
                "gas_statistics": {
                    "average": int(deployable['gas_used'].mean()) if len(deployable) > 0 else None,
                    "min": int(deployable['gas_used'].min()) if len(deployable) > 0 else None,
                    "max": int(deployable['gas_used'].max()) if len(deployable) > 0 else None,
                    "median": int(deployable['gas_used'].median()) if len(deployable) > 0 else None
                }
            }
        
        with open(gas_json_path, 'w', encoding='utf-8') as f:
            json.dump({
                "analysis_timestamp": datetime.now().isoformat(),
                "statistics": statistics,
                "total_contracts_analyzed": len(df),
                "total_deployable": int(df['deployment_success'].sum())
            }, f, indent=2)
        
        print(f"[SAVED] Gas consumption JSON: {gas_json_path}")
        
        # Print summary
        self.print_summary(df)
        
        # Update final_analysis.json with gas data
        self.update_final_analysis(statistics)
    
    def print_summary(self, df: pd.DataFrame):
        """Print summary statistics."""
        print("\n" + "=" * 80)
        print(" " * 25 + "GAS CONSUMPTION SUMMARY")
        print("=" * 80)
        
        for model in df['model'].unique():
            model_data = df[df['model'] == model]
            deployable = model_data[model_data['deployment_success'] == True]
            
            print(f"\n[{model}]")
            print(f"  Total contracts:           {len(model_data)}")
            print(f"  Deployment compilation:    {model_data['deployment_compilation_success'].sum()} ({model_data['deployment_compilation_success'].mean()*100:.1f}%)")
            print(f"  Deployment success:        {model_data['deployment_success'].sum()} ({model_data['deployment_success'].mean()*100:.1f}%)")
            
            if len(deployable) > 0:
                print(f"  Average gas:               {deployable['gas_used'].mean():,.0f}")
                print(f"  Min gas:                   {deployable['gas_used'].min():,}")
                print(f"  Max gas:                   {deployable['gas_used'].max():,}")
                print(f"  Median gas:                {deployable['gas_used'].median():,.0f}")
        
        print("\n" + "=" * 80 + "\n")
    
    def update_final_analysis(self, gas_statistics: Dict):
        """Update final_analysis.json with gas consumption data."""
        if not self.final_analysis_path.exists():
            print("[INFO] final_analysis.json not found, skipping update")
            return
        
        try:
            with open(self.final_analysis_path, 'r', encoding='utf-8') as f:
                final_analysis = json.load(f)
            
            # Add gas consumption data to each model's statistics
            for model, gas_stats in gas_statistics.items():
                if model in final_analysis.get("statistics", {}):
                    final_analysis["statistics"][model]["gas_consumption"] = gas_stats
            
            # Save updated analysis
            with open(self.final_analysis_path, 'w', encoding='utf-8') as f:
                json.dump(final_analysis, f, indent=2)
            
            print(f"[UPDATED] final_analysis.json with gas consumption data")
            
        except Exception as e:
            print(f"[WARNING] Failed to update final_analysis.json: {e}")


def main():
    analyzer = GasConsumptionAnalyzer("output")
    
    try:
        analyzer.analyze_gas_consumption()
        
        print("=" * 80)
        print("[SUCCESS] Gas consumption analysis complete!")
        print("=" * 80)
        
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Analysis stopped by user")
        analyzer.stop_anvil()
    except Exception as e:
        print(f"\n\n[ERROR] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        analyzer.stop_anvil()


if __name__ == '__main__':
    main()