# LLM Vulnerability Detection Evaluation Pipeline

This pipeline evaluates the vulnerability detection capabilities of open-source LLMs on the SmartBugs curated dataset.

## Overview

The pipeline consists of three main scripts that work together:

1. **`llm_predictions.py`** - Generates predictions from LLMs
2. **`evaluate_predictions.py`** - Evaluates predictions against ground truth
3. **`visualize_results.py`** - Creates visualizations and reports

## Quick Start

### Prerequisites

```bash
# Install required packages
pip install requests matplotlib seaborn numpy

# Make sure Ollama is running with models installed
ollama pull llama3.2
ollama pull codellama
```

### Step 1: Generate Predictions

Run LLMs on all Solidity files in the dataset:

```bash
python llm_predictions.py --dataset_dir dataset_clean
```

**Options:**
- `--dataset_dir`: Path to dataset directory (default: `dataset_clean`)
- `--base_url`: Ollama API URL (default: `http://localhost:11434`)
- `--models`: Specific models to use (default: all available)
- `--timeout`: Timeout per contract in seconds (default: `180`)
- `--output`: Output file path (default: `output/llm_vuln_results.json`)

**Example with specific models:**
```bash
python llm_predictions.py \
  --dataset_dir dataset_clean \
  --models llama3.2 codellama \
  --timeout 300
```

### Step 2: Evaluate Predictions

Compare predictions against ground truth labels:

```bash
python evaluate_predictions.py \
  --predictions output/llm_vuln_results.json \
  --ground_truth dataset_clean/dataset_index.json
```

**Options:**
- `--predictions`: Path to predictions JSON (default: `output/llm_vuln_results.json`)
- `--ground_truth`: Path to ground truth JSON (default: `dataset_clean/dataset_index.json`)
- `--output`: Output file path (default: `output/evaluation_results.json`)
- `--models`: Specific models to evaluate (default: all)

### Step 3: Generate Visualizations

Create charts and markdown report:

```bash
python visualize_results.py \
  --results output/evaluation_results.json
```

**Options:**
- `--results`: Path to evaluation results (default: `output/evaluation_results.json`)
- `--output_dir`: Output directory (default: `output/visualizations`)

## Output Structure

After running the complete pipeline, you'll have:

```
output/
├── llm_vuln_results.json          # Raw LLM predictions
├── evaluation_results.json        # Computed metrics
└── visualizations/
    ├── evaluation_report.md       # Comprehensive markdown report
    ├── model_comparison.png       # Cross-model comparison chart
    ├── confusion_matrix_*.png     # One per model
    ├── per_class_metrics_*.png    # One per model
    └── prediction_distribution_*.png  # One per model
```

## Metrics Explained

### Type Detection Metrics
- **Accuracy**: Overall percentage of correct vulnerability type predictions
- **Precision**: Of all predictions of type X, what % were correct?
- **Recall**: Of all actual vulnerabilities of type X, what % were detected?
- **F1-Score**: Harmonic mean of precision and recall

### Line Localization Metrics
- **Exact Match Rate**: Predicted line exactly matches a ground truth line
- **Within-5 Rate**: Predicted line is within 5 lines of a ground truth line
- Only computed when the vulnerability type is correctly predicted

### Confusion Matrix
Shows which vulnerability types are confused with each other (rows = true labels, columns = predicted labels)

## Dataset Structure

The SmartBugs curated dataset should have this structure:

```
dataset_clean/
├── dataset_index.json           # Ground truth labels
├── access_control/
│   ├── contract1.sol
│   └── contract2.sol
├── reentrancy/
│   ├── contract3.sol
│   └── contract4.sol
├── arithmetic/
├── bad_randomness/
├── denial_of_service/
├── front_running/
├── time_manipulation/
├── unchecked_low_level_calls/
├── short_addresses/
└── uninitialized_storage/
```

## Vulnerability Categories

The evaluation supports the following vulnerability types:
- **reentrancy**: Re-entrancy attacks
- **access_control**: Missing or incorrect authorization checks
- **arithmetic**: Integer overflow/underflow
- **unchecked_low_level_calls**: Unchecked call/delegatecall return values
- **denial_of_service**: DoS vulnerabilities
- **bad_randomness**: Predictable randomness sources
- **front_running**: Transaction ordering dependence
- **time_manipulation**: Timestamp dependence
- **short_addresses**: Short address attacks
- **uninitialized_storage**: Uninitialized storage pointers
- **none**: No vulnerability detected

## Workflow Example

Complete workflow with custom settings:

```bash
# Step 1: Generate predictions (limit to 2 models)
python llm_predictions.py \
  --dataset_dir dataset_clean \
  --models llama3.2 mistral \
  --timeout 240 \
  --output output/llm_vuln_results.json

# Step 2: Evaluate predictions
python evaluate_predictions.py \
  --predictions output/llm_vuln_results.json \
  --ground_truth dataset_clean/dataset_index.json \
  --output output/evaluation_results.json

# Step 3: Create visualizations
python visualize_results.py \
  --results output/evaluation_results.json \
  --output_dir output/visualizations
```

## Troubleshooting

### No models found
- Make sure Ollama is running: `ollama list`
- Install models: `ollama pull llama3.2`

### Timeout errors
- Increase timeout: `--timeout 300`
- Use smaller/faster models
- Process fewer files for testing

### Missing ground truth files
- Check that `dataset_index.json` exists in your dataset directory
- Ensure file names in predictions match those in ground truth

### Import errors
- Install missing packages: `pip install matplotlib seaborn numpy requests`

## Tips

1. **Start small**: Test with 1-2 models first
2. **Monitor progress**: Scripts print progress as they run
3. **Check outputs**: Review JSON files before visualization
4. **Compare models**: Use multiple models to see which performs best
5. **Adjust timeout**: Longer for complex contracts, shorter for simple ones

## Output Files Details

### llm_vuln_results.json
Contains raw predictions from each model with metadata about processing time, errors, etc.

### evaluation_results.json
Contains computed metrics including:
- Overall accuracy
- Per-class precision/recall/F1
- Confusion matrices
- Line localization statistics

### evaluation_report.md
Human-readable report with:
- Summary tables
- Embedded charts
- Key insights
- Detailed per-model analysis

## License

This evaluation pipeline is designed for research purposes to assess LLM capabilities in smart contract security analysis.
