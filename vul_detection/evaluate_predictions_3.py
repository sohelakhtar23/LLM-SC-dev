import os
import json
import argparse
from typing import Dict, List, Optional, Any, Tuple


def load_json(filepath: str) -> Any:
    """Load JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_vulnerability_type(vuln_type: Any) -> Optional[str]:
    """Normalize vulnerability type names to standard format."""
    if vuln_type is None:
        return None
    
    v = str(vuln_type).strip().lower().replace(" ", "_").replace("-", "_")
    
    # Mapping for common variations
    mapping = {
        "reentrancy": "reentrancy",
        "bad_randomness": "bad_randomness",
        "badrandomness": "bad_randomness",
        "randomness": "bad_randomness",
        "predictable_randomness": "bad_randomness",
        "access_control": "access_control",
        "accesscontrol": "access_control",
        "arithmetic": "arithmetic",
        "unchecked_low_level_calls": "unchecked_low_level_calls",
        "unchecked_ll_calls": "unchecked_low_level_calls",
        "uncheckedlowlevelcalls": "unchecked_low_level_calls",
        "denial_of_service": "denial_of_service",
        "denialofservice": "denial_of_service",
        "dos": "denial_of_service",
        "front_running": "front_running",
        "frontrunning": "front_running",
        "time_manipulation": "time_manipulation",
        "timemanipulation": "time_manipulation",
        "short_addresses": "short_addresses",
        "shortaddresses": "short_addresses",
        "other": "other",
        "none": None,
        "null": None,
        "": None,
    }
    
    return mapping.get(v, v)


def build_ground_truth_index(gt_data: Dict[str, Any]) -> Dict[str, Tuple[Optional[str], List[int]]]:
    """
    Build ground truth index from dataset_index.json.
    
    Returns:
        Dict mapping filename -> (vulnerability_type, list_of_lines)
    """
    gt_index = {}
    
    for key, entry in gt_data.items():
        # Get filename
        filename = entry.get("name", key)
        basename = os.path.basename(filename)
        
        # Get vulnerabilities
        vulns = entry.get("vulnerabilities", [])
        
        if not vulns:
            # No vulnerability
            gt_index[basename] = (None, [])
            continue
        
        # Take first vulnerability (dataset has one per contract)
        vuln = vulns[0] if isinstance(vulns, list) else {}
        vuln_type = normalize_vulnerability_type(vuln.get("category"))
        
        # Get lines
        lines_raw = vuln.get("lines", [])
        lines = []
        for line in lines_raw:
            try:
                lines.append(int(line))
            except:
                pass
        lines = sorted(set(lines))
        
        gt_index[basename] = (vuln_type, lines)
    
    return gt_index


def calculate_metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
    """Calculate precision, recall, and F1 score."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4)
    }


def calculate_line_accuracy(
    pred_lines: List[int],
    gt_lines: List[int],
    within_k: int = 5
) -> Dict[str, Any]:
    """
    Calculate line localization accuracy.
    
    Args:
        pred_lines: Predicted line numbers
        gt_lines: Ground truth line numbers
        within_k: Consider prediction correct if within k lines
    
    Returns:
        Dict with exact match and within-k match info
    """
    if not pred_lines or not gt_lines:
        return {
            "exact_match": False,
            f"within_{within_k}": False,
            "min_distance": None
        }
    
    # Check exact match
    exact_match = any(pl in gt_lines for pl in pred_lines)
    
    # Calculate minimum distance
    min_dist = min(
        abs(pl - gl)
        for pl in pred_lines
        for gl in gt_lines
    )
    
    within_k_match = min_dist <= within_k
    
    return {
        "exact_match": exact_match,
        f"within_{within_k}": within_k_match,
        "min_distance": min_dist
    }


def evaluate_model(
    predictions: List[Dict[str, Any]],
    gt_index: Dict[str, Tuple[Optional[str], List[int]]],
    vulnerability_classes: List[str]
) -> Dict[str, Any]:
    """
    Evaluate predictions for a single model.
    
    Returns:
        Dictionary with overall accuracy, per-class metrics, and confusion matrix
    """
    # Collect predictions and ground truth
    y_true = []
    y_pred = []
    line_accuracy_results = []
    missing_files = []
    
    for pred_item in predictions:
        filename = os.path.basename(pred_item.get("file", ""))
        
        # Get ground truth
        if filename not in gt_index:
            missing_files.append(filename)
            continue
        
        gt_type, gt_lines = gt_index[filename]
        
        # Get prediction
        prediction = pred_item.get("prediction", {})
        pred_type = normalize_vulnerability_type(prediction.get("vulnerability_type"))
        pred_lines = prediction.get("lines", [])
        if not isinstance(pred_lines, list):
            pred_lines = [pred_lines] if pred_lines is not None else []
        
        y_true.append(gt_type)
        y_pred.append(pred_type)
        
        # Calculate line accuracy only if types match and both are vulnerable
        if gt_type is not None and pred_type == gt_type and gt_lines:
            line_acc = calculate_line_accuracy(pred_lines, gt_lines)
            line_accuracy_results.append(line_acc)
    
    # Overall accuracy
    total = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / total if total > 0 else 0.0
    
    # Per-class metrics
    # Include None (no vulnerability) as a class
    all_classes = vulnerability_classes + [None]
    per_class_metrics = {}
    
    for vuln_class in all_classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == vuln_class and p == vuln_class)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != vuln_class and p == vuln_class)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == vuln_class and p != vuln_class)
        
        class_name = vuln_class if vuln_class else "none"
        metrics = calculate_metrics(tp, fp, fn)
        
        per_class_metrics[class_name] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "support": sum(1 for t in y_true if t == vuln_class),
            **metrics
        }
    
    # Confusion matrix
    confusion_matrix = {}
    for true_class in all_classes:
        true_name = true_class if true_class else "none"
        confusion_matrix[true_name] = {}
        for pred_class in all_classes:
            pred_name = pred_class if pred_class else "none"
            count = sum(1 for t, p in zip(y_true, y_pred) if t == true_class and p == pred_class)
            confusion_matrix[true_name][pred_name] = count
    
    # Line localization metrics (only for type-correct vulnerable predictions)
    line_metrics = {}
    if line_accuracy_results:
        exact_matches = sum(1 for r in line_accuracy_results if r["exact_match"])
        within_5_matches = sum(1 for r in line_accuracy_results if r["within_5"])
        total_eligible = len(line_accuracy_results)
        
        line_metrics = {
            "eligible_cases": total_eligible,
            "exact_match_count": exact_matches,
            "exact_match_rate": round(exact_matches / total_eligible, 4) if total_eligible > 0 else 0.0,
            "within_5_count": within_5_matches,
            "within_5_rate": round(within_5_matches / total_eligible, 4) if total_eligible > 0 else 0.0,
        }
    
    return {
        "total_samples": total,
        "accuracy": round(accuracy, 4),
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": confusion_matrix,
        "line_localization": line_metrics,
        "missing_ground_truth": sorted(missing_files) if missing_files else []
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM vulnerability predictions against ground truth"
    )
    parser.add_argument(
        "--predictions",
        type=str,
        default="output/llm_vuln_results.json",
        help="Path to predictions JSON file"
    )
    parser.add_argument(
        "--ground_truth",
        type=str,
        default="dataset_clean/dataset_index.json",
        help="Path to ground truth JSON file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output/evaluation_results.json",
        help="Output file for evaluation results"
    )
    parser.add_argument(
        "--models",
        nargs="*",
        default=None,
        help="Specific models to evaluate (if not provided, evaluates all)"
    )
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading predictions from: {args.predictions}")
    predictions_data = load_json(args.predictions)
    
    print(f"Loading ground truth from: {args.ground_truth}")
    gt_data = load_json(args.ground_truth)
    
    # Build ground truth index
    gt_index = build_ground_truth_index(gt_data)
    print(f"Found {len(gt_index)} contracts in ground truth")
    
    # Define vulnerability classes (standard SmartBugs categories)
    vulnerability_classes = [
        "reentrancy",
        "access_control",
        "arithmetic",
        "unchecked_low_level_calls",
        "denial_of_service",
        "bad_randomness",
        "front_running",
        "time_manipulation",
        "short_addresses",
        "other"
    ]
    
    # Get models to evaluate
    model_names = [
        key for key, value in predictions_data.items()
        if not key.startswith("_") and isinstance(value, list)
    ]
    
    if args.models:
        model_names = [m for m in model_names if m in args.models]
    
    print(f"Evaluating {len(model_names)} model(s): {', '.join(model_names)}")
    
    # Evaluate each model
    results = {
        "evaluation_metadata": {
            "predictions_file": os.path.abspath(args.predictions),
            "ground_truth_file": os.path.abspath(args.ground_truth),
            "total_ground_truth_samples": len(gt_index),
            "vulnerability_classes": vulnerability_classes
        },
        "models": {}
    }
    
    for model_name in model_names:
        print(f"\nEvaluating model: {model_name}")
        model_predictions = predictions_data[model_name]
        
        model_results = evaluate_model(
            model_predictions,
            gt_index,
            vulnerability_classes
        )
        
        results["models"][model_name] = model_results
        
        # Print summary
        print(f"  Total samples: {model_results['total_samples']}")
        print(f"  Accuracy: {model_results['accuracy']:.2%}")
        if model_results['line_localization']:
            print(f"  Line within-5 rate: {model_results['line_localization']['within_5_rate']:.2%}")
    
    # Save results
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"Evaluation results saved to: {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()