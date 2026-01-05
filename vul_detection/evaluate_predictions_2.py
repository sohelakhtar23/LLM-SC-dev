import os
import json
import argparse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# -------------------------
# Utilities
# -------------------------

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf8") as f:
        return json.load(f)


def safe_div(n: float, d: float) -> float:
    return float(n) / float(d) if d else 0.0


def prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    """Precision / Recall / F1 for a single class (one-vs-rest)."""
    p = safe_div(tp, tp + fp)
    r = safe_div(tp, tp + fn)
    f1 = safe_div(2 * p * r, p + r) if (p + r) else 0.0
    return {"precision": p, "recall": r, "f1": f1}


def normalize_vuln_type(v: Any) -> Optional[str]:
    """Normalize either prediction or ground-truth type strings to canonical labels."""
    if v is None:
        return None
    s = str(v).strip().lower()
    mapping = {
        # canonical
        "reentrancy": "reentrancy",
        "bad_randomness": "bad_randomness",
        "access_control": "access_control",
        "unchecked_ll_calls": "unchecked_ll_calls",

        # common variants
        "bad randomness": "bad_randomness",
        "randomness": "bad_randomness",
        "predictable_randomness": "bad_randomness",
        "predictable randomness": "bad_randomness",

        "access control": "access_control",

        "unchecked low level calls": "unchecked_ll_calls",
        "unchecked low-level calls": "unchecked_ll_calls",
        "unchecked_low_level_calls": "unchecked_ll_calls",
        "unchecked low level call": "unchecked_ll_calls",
        "unchecked_low_level_call": "unchecked_ll_calls",

        "none": None,
        "null": None,
        "": None,
    }
    return mapping.get(s, s)


def label_to_key(label: Optional[str]) -> str:
    """Serialize None as the explicit 'null' class label."""
    return "null" if label is None else str(label)


# -------------------------
# Ground truth extraction
# -------------------------

def build_gt_index(gt: Dict[str, Any]) -> Dict[str, Tuple[Optional[str], List[int]]]:
    """
    Return mapping:
        basename.sol -> (vuln_type_or_None, sorted_unique_lines_list)

    If a file has no vulnerabilities in GT, vuln_type is None and lines is [].
    """
    out: Dict[str, Tuple[Optional[str], List[int]]] = {}

    for key, entry in gt.items():
        name = entry.get("name") or key
        base = os.path.basename(name)

        vulns = entry.get("vulnerabilities") or []
        if not vulns:
            out[base] = (None, [])
            continue

        # Most datasets have exactly one vulnerability entry.
        # If multiple exist, we pick the first as the representative label.
        v0 = vulns[0] if isinstance(vulns, list) else {}
        cat = normalize_vuln_type(v0.get("category"))

        lines_raw = v0.get("lines") or []
        lines: List[int] = []
        for x in lines_raw:
            try:
                lines.append(int(x))
            except Exception:
                continue
        lines = sorted(set(lines))

        out[base] = (cat, lines)

    return out


# -------------------------
# Metrics (5-class: 4 vulns + null)
# -------------------------

def compute_multiclass_metrics(
    y_true: List[Optional[str]],
    y_pred: List[Optional[str]],
    labels: List[Optional[str]],
) -> Dict[str, Any]:
    """
    Multiclass metrics treating {reentrancy, bad_randomness, access_control,
    unchecked_ll_calls, null} as 5 mutually exclusive classes.

    Returns:
      - accuracy
      - per-class precision/recall/F1 (+ tp/fp/fn)
      - confusion matrix
    """
    assert len(y_true) == len(y_pred)

    n = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)

    per_label: Dict[str, Any] = {}
    for lab in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == lab and p == lab)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != lab and p == lab)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == lab and p != lab)
        actual_no = sum(1 for t in y_true if t == lab)
        m = prf(tp, fp, fn)
        per_label[label_to_key(lab)] = {
            "actual_no": actual_no,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            **m,
        }

    # Confusion matrix
    cm: Dict[str, Dict[str, int]] = {
        label_to_key(t): {label_to_key(p): 0 for p in labels} for t in labels
    }
    for t, p in zip(y_true, y_pred):
        cm[label_to_key(t)][label_to_key(p)] += 1

    return {
        "n": n,
        "accuracy": safe_div(correct, n),
        "per_label": per_label,
        "confusion_matrix": cm,
    }


def closest_abs_distance(pred_line: int, gt_lines: List[int]) -> int:
    return min(abs(pred_line - gl) for gl in gt_lines)


def compute_localization_within5(
    y_true_type: List[Optional[str]],
    y_pred_type: List[Optional[str]],
    y_pred_line: List[Optional[int]],
    gt_lines_list: List[List[int]],
) -> Dict[str, Any]:
    """
    Line localization computed ONLY when:
      - ground truth is vulnerable (non-null)
      - predicted type matches GT type

    Reports within-5 only (no exact / within-1/2 / MAE).
    """
    assert len(y_true_type) == len(y_pred_type) == len(y_pred_line) == len(gt_lines_list)

    eligible = 0
    line_predicted = 0
    within_5 = 0

    for t_type, p_type, p_line, gt_lines in zip(y_true_type, y_pred_type, y_pred_line, gt_lines_list):
        if t_type is None:
            continue
        if p_type != t_type:
            continue

        eligible += 1

        if p_line is None or not gt_lines:
            continue
        line_predicted += 1

        d = 0 if (p_line in gt_lines) else closest_abs_distance(p_line, gt_lines)
        if d <= 5:
            within_5 += 1

    return {
        "eligible_count_type_correct_and_vulnerable": eligible,
        "line_predicted_count": line_predicted,
        "within_5_count": within_5,
        "within_5_rate": safe_div(within_5, eligible),
    }


# -------------------------
# Main
# -------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate model predictions vs ground-truth labels.")
    ap.add_argument("--predictions", required=True, help="Path to LLM output JSON (e.g., llm_vuln_results*.json)")
    ap.add_argument("--ground_truth", required=True, help="Path to ground-truth label JSON")
    ap.add_argument("--output_dir", default=".", help="Directory to save evaluation report JSON")
    ap.add_argument(
        "--models",
        nargs="*",
        default=None,
        help="Optional subset of model names to evaluate (must match keys in predictions JSON)",
    )
    args = ap.parse_args()

    pred_root = load_json(args.predictions)
    gt_root = load_json(args.ground_truth)

    gt_index = build_gt_index(gt_root)

    # Determine which model keys exist in predictions JSON
    model_keys = [k for k, v in pred_root.items() if not k.startswith("_") and isinstance(v, list)]
    if args.models:
        model_keys = [m for m in model_keys if m in set(args.models)]

    # 5 classes (4 vulnerabilities + null)
    labels: List[Optional[str]] = ["reentrancy", "bad_randomness", "access_control", "unchecked_ll_calls", None]

    report: Dict[str, Any] = {
        "run_at": datetime.now().isoformat(timespec="seconds"),
        "predictions_file": os.path.abspath(args.predictions),
        "ground_truth_file": os.path.abspath(args.ground_truth),
        "labels": [label_to_key(x) for x in labels],  # includes explicit "null"
        "models": {},
        "missing_ground_truth": {},
    }

    for model in model_keys:
        rows = pred_root.get(model, [])
        y_true_type: List[Optional[str]] = []
        y_pred_type: List[Optional[str]] = []
        y_pred_line: List[Optional[int]] = []
        gt_lines_list: List[List[int]] = []

        missing: List[str] = []

        for item in rows:
            rel = item.get("file") or item.get("path") or ""
            base = os.path.basename(rel)

            gt = gt_index.get(base)
            if gt is None:
                missing.append(base)
                continue

            gt_type, gt_lines = gt

            pred = (item.get("prediction") or {})
            p_type = normalize_vuln_type(pred.get("vulnerability_type"))

            p_line_raw = pred.get("line")
            try:
                p_line = int(p_line_raw) if p_line_raw is not None else None
            except Exception:
                p_line = None

            y_true_type.append(gt_type)
            y_pred_type.append(p_type)
            y_pred_line.append(p_line)
            gt_lines_list.append(gt_lines)

        # Type metrics (5-class)
        type_metrics = compute_multiclass_metrics(y_true_type, y_pred_type, labels)

        # Localization (within-5 only, computed on type-correct vulnerable cases)
        localization = compute_localization_within5(y_true_type, y_pred_type, y_pred_line, gt_lines_list)

        # Combined correctness: type correct AND within-5 line (over ALL vulnerable GT samples)
        both_within5 = 0
        vulnerable_count = sum(1 for t in y_true_type if t is not None)
        for t_type, p_type, p_line, gt_lines in zip(y_true_type, y_pred_type, y_pred_line, gt_lines_list):
            if t_type is None:
                continue
            if p_type != t_type:
                continue
            if p_line is None or not gt_lines:
                continue
            d = 0 if (p_line in gt_lines) else closest_abs_distance(p_line, gt_lines)
            if d <= 5:
                both_within5 += 1

        report["models"][model] = {
            "n_evaluated": len(y_true_type),
            "n_vulnerable": vulnerable_count,
            "type_metrics_5class": type_metrics,
            "localization_within5": localization,
            "type_and_line_within5_correct_rate": safe_div(both_within5, vulnerable_count) if vulnerable_count else 0.0,
        }

        if missing:
            report["missing_ground_truth"][model] = sorted(set(missing))

    os.makedirs(args.output_dir, exist_ok=True)
    out_name = "evaluation_results" + datetime.now().strftime("%b%d_%H_%M_%S" + ".json")
    out_path = os.path.join(args.output_dir, out_name)

    with open(out_path, "w", encoding="utf8") as f:
        json.dump(report, f, indent=2)

    print(f"Saved evaluation report: {out_path}")


if __name__ == "__main__":
    main()
