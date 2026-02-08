import os
import json
import argparse
from typing import Dict, List, Any
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime


def load_json(filepath: str) -> Any:
    """Load JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_confusion_matrix(
    confusion_matrix: Dict[str, Dict[str, int]],
    model_name: str,
    output_dir: str
):
    """Generate and save confusion matrix heatmap."""
    # Get all classes
    classes = sorted(confusion_matrix.keys())
    
    # Create matrix
    matrix = np.zeros((len(classes), len(classes)))
    for i, true_class in enumerate(classes):
        for j, pred_class in enumerate(classes):
            matrix[i, j] = confusion_matrix[true_class].get(pred_class, 0)
    
    # Create figure
    plt.figure(figsize=(10, 8))
    sns.heatmap(
        matrix,
        annot=True,
        fmt='g',
        cmap='Blues',
        xticklabels=classes,
        yticklabels=classes,
        cbar_kws={'label': 'Count'}
    )
    plt.title(f'Confusion Matrix - {model_name}', fontsize=14, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    
    # Save
    filename = f"confusion_matrix_{model_name.replace(':', '_').replace('/', '_')}.png"
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filename


def plot_per_class_metrics(
    per_class_metrics: Dict[str, Dict[str, Any]],
    model_name: str,
    output_dir: str
):
    """Generate bar chart for per-class precision, recall, and F1."""
    classes = sorted(per_class_metrics.keys())
    
    precision = [per_class_metrics[c]['precision'] for c in classes]
    recall = [per_class_metrics[c]['recall'] for c in classes]
    f1 = [per_class_metrics[c]['f1'] for c in classes]
    
    x = np.arange(len(classes))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    bars1 = ax.bar(x - width, precision, width, label='Precision', color='#3498db')
    bars2 = ax.bar(x, recall, width, label='Recall', color='#2ecc71')
    bars3 = ax.bar(x + width, f1, width, label='F1-Score', color='#e74c3c')
    
    ax.set_xlabel('Vulnerability Class', fontsize=12)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title(f'Per-Class Metrics - {model_name}', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(classes, rotation=45, ha='right')
    ax.legend()
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    
    filename = f"per_class_metrics_{model_name.replace(':', '_').replace('/', '_')}.png"
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filename


def plot_model_comparison(
    results: Dict[str, Dict[str, Any]],
    output_dir: str
):
    """Generate comparison chart across all models."""
    models = sorted(results.keys())
    
    accuracy = [results[m]['accuracy'] for m in models]
    
    # Get line localization rates if available
    within_1_rates = []
    for m in models:
        line_loc = results[m].get('line_localization', {})
        within_1_rates.append(line_loc.get('within_1_rate', 0.0))
    
    x = np.arange(len(models))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    bars1 = ax.bar(x - width/2, accuracy, width, label='Overall Accuracy', color='#3498db')
    bars2 = ax.bar(x + width/2, within_1_rates, width, label='Line Within-1 Rate', color='#9b59b6')
    
    ax.set_xlabel('Model', fontsize=12)
    ax.set_ylabel('Rate', fontsize=12)
    ax.set_title('Model Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.legend()
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.2%}',
                       ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    
    filename = "model_comparison.png"
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filename


def plot_vulnerability_distribution(
    per_class_metrics: Dict[str, Dict[str, Any]],
    model_name: str,
    output_dir: str
):
    """Generate pie chart showing distribution of predictions."""
    classes = []
    counts = []
    
    for vuln_class, metrics in per_class_metrics.items():
        tp = metrics['tp']
        fp = metrics['fp']
        total_predicted = tp + fp
        if total_predicted > 0:
            classes.append(vuln_class)
            counts.append(total_predicted)
    
    if not counts:
        return None
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors = plt.cm.Set3(np.linspace(0, 1, len(classes)))
    wedges, texts, autotexts = ax.pie(
        counts,
        labels=classes,
        autopct='%1.1f%%',
        colors=colors,
        startangle=90
    )
    
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    
    ax.set_title(f'Prediction Distribution - {model_name}', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    
    filename = f"prediction_distribution_{model_name.replace(':', '_').replace('/', '_')}.png"
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    
    return filename


def generate_markdown_report(
    evaluation_data: Dict[str, Any],
    output_dir: str,
    chart_files: Dict[str, Dict[str, str]]
) -> str:
    """Generate detailed markdown report."""
    md_lines = []
    
    # Header
    md_lines.append("# LLM Vulnerability Detection Evaluation Report")
    md_lines.append("")
    md_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md_lines.append("")
    
    # Metadata
    metadata = evaluation_data.get('evaluation_metadata', {})
    md_lines.append("## Dataset Information")
    md_lines.append("")
    md_lines.append(f"- **Ground Truth File:** `{os.path.basename(metadata.get('ground_truth_file', 'N/A'))}`")
    md_lines.append(f"- **Total Samples:** {metadata.get('total_ground_truth_samples', 'N/A')}")
    md_lines.append(f"- **Vulnerability Classes:** {', '.join(metadata.get('vulnerability_classes', []))}")
    md_lines.append("")
    
    # Model comparison
    models_data = evaluation_data.get('models', {})
    
    if len(models_data) > 1:
        md_lines.append("## Overall Model Comparison")
        md_lines.append("")
        
        if 'model_comparison.png' in chart_files:
            md_lines.append(f"![Model Comparison]({chart_files['model_comparison.png']})")
            md_lines.append("")
        
        # Comparison table
        md_lines.append("| Model | Accuracy | Precision (Avg) | Recall (Avg) | F1 (Avg) | Line Within-1 |")
        md_lines.append("|-------|----------|-----------------|--------------|----------|---------------|")
        
        for model_name in sorted(models_data.keys()):
            model_data = models_data[model_name]
            accuracy = model_data.get('accuracy', 0)
            
            # Calculate macro averages
            per_class = model_data.get('per_class_metrics', {})
            precisions = [m['precision'] for m in per_class.values() if m['support'] > 0]
            recalls = [m['recall'] for m in per_class.values() if m['support'] > 0]
            f1s = [m['f1'] for m in per_class.values() if m['support'] > 0]
            
            avg_precision = np.mean(precisions) if precisions else 0
            avg_recall = np.mean(recalls) if recalls else 0
            avg_f1 = np.mean(f1s) if f1s else 0
            
            line_loc = model_data.get('line_localization', {})
            within_1 = line_loc.get('within_1_rate', 0)
            
            md_lines.append(
                f"| {model_name} | {accuracy:.2%} | {avg_precision:.2%} | "
                f"{avg_recall:.2%} | {avg_f1:.2%} | {within_1:.2%} |"
            )
        
        md_lines.append("")
    
    # Detailed results per model
    for model_name in sorted(models_data.keys()):
        model_data = models_data[model_name]
        
        md_lines.append(f"## Model: {model_name}")
        md_lines.append("")
        
        # Overall metrics
        md_lines.append("### Overall Performance")
        md_lines.append("")
        md_lines.append(f"- **Total Samples Evaluated:** {model_data.get('total_samples', 0)}")
        md_lines.append(f"- **Overall Accuracy:** {model_data.get('accuracy', 0):.2%}")
        md_lines.append("")
        
        # Line localization
        line_loc = model_data.get('line_localization', {})
        if line_loc:
            md_lines.append("### Line Localization")
            md_lines.append("")
            md_lines.append(f"- **Eligible Cases (Type-Correct):** {line_loc.get('eligible_cases', 0)}")
            md_lines.append(f"- **Exact Match Rate:** {line_loc.get('exact_match_rate', 0):.2%}")
            md_lines.append(f"- **Within-1 Line Rate:** {line_loc.get('within_1_rate', 0):.2%}")
            md_lines.append("")
        
        # Per-class metrics chart
        model_charts = chart_files.get(model_name, {})
        if 'per_class_metrics' in model_charts:
            md_lines.append("### Per-Class Metrics")
            md_lines.append("")
            md_lines.append(f"![Per-Class Metrics]({model_charts['per_class_metrics']})")
            md_lines.append("")
        
        # Per-class table
        md_lines.append("### Detailed Per-Class Performance")
        md_lines.append("")
        md_lines.append("| Class | Support | TP | FP | FN | Precision | Recall | F1-Score |")
        md_lines.append("|-------|---------|----|----|-------|-----------|--------|----------|")
        
        per_class = model_data.get('per_class_metrics', {})
        for vuln_class in sorted(per_class.keys()):
            metrics = per_class[vuln_class]
            md_lines.append(
                f"| {vuln_class} | {metrics['support']} | {metrics['tp']} | "
                f"{metrics['fp']} | {metrics['fn']} | {metrics['precision']:.2%} | "
                f"{metrics['recall']:.2%} | {metrics['f1']:.2%} |"
            )
        
        md_lines.append("")
        
        # Confusion matrix
        if 'confusion_matrix' in model_charts:
            md_lines.append("### Confusion Matrix")
            md_lines.append("")
            md_lines.append(f"![Confusion Matrix]({model_charts['confusion_matrix']})")
            md_lines.append("")
        
        # Prediction distribution
        if 'prediction_distribution' in model_charts:
            md_lines.append("### Prediction Distribution")
            md_lines.append("")
            md_lines.append(f"![Prediction Distribution]({model_charts['prediction_distribution']})")
            md_lines.append("")
        
        # Missing files
        missing = model_data.get('missing_ground_truth', [])
        if missing:
            md_lines.append("### Missing Ground Truth")
            md_lines.append("")
            md_lines.append(f"The following {len(missing)} file(s) were predicted but not found in ground truth:")
            md_lines.append("")
            for f in missing[:10]:  # Show max 10
                md_lines.append(f"- `{f}`")
            if len(missing) > 10:
                md_lines.append(f"- ... and {len(missing) - 10} more")
            md_lines.append("")
        
        md_lines.append("---")
        md_lines.append("")
    
    # Key insights
    md_lines.append("## Key Insights")
    md_lines.append("")
    
    if len(models_data) > 1:
        # Find best model
        best_accuracy_model = max(models_data.items(), key=lambda x: x[1].get('accuracy', 0))
        md_lines.append(f"- **Best Overall Accuracy:** {best_accuracy_model[0]} ({best_accuracy_model[1]['accuracy']:.2%})")
        
        # Find best line localization
        best_line_model = max(
            models_data.items(),
            key=lambda x: x[1].get('line_localization', {}).get('within_1_rate', 0)
        )
        within_1 = best_line_model[1].get('line_localization', {}).get('within_1_rate', 0)
        if within_1 > 0:
            md_lines.append(f"- **Best Line Localization:** {best_line_model[0]} ({within_1:.2%} within 1 line)")
        md_lines.append("")
    
    # Vulnerability-specific insights
    md_lines.append("### Vulnerability Detection Performance")
    md_lines.append("")
    
    # Aggregate across all models
    all_classes = set()
    for model_data in models_data.values():
        all_classes.update(model_data.get('per_class_metrics', {}).keys())
    
    for vuln_class in sorted(all_classes):
        if vuln_class == 'none':
            continue
        
        f1_scores = []
        for model_name, model_data in models_data.items():
            per_class = model_data.get('per_class_metrics', {})
            if vuln_class in per_class and per_class[vuln_class]['support'] > 0:
                f1_scores.append((model_name, per_class[vuln_class]['f1']))
        
        if f1_scores:
            best = max(f1_scores, key=lambda x: x[1])
            md_lines.append(f"- **{vuln_class}:** Best F1 = {best[1]:.2%} ({best[0]})")
    
    md_lines.append("")
    
    # Save markdown
    md_content = "\n".join(md_lines)
    md_filepath = os.path.join(output_dir, "evaluation_report.md")
    with open(md_filepath, "w", encoding="utf-8") as f:
        f.write(md_content)
    
    return md_filepath


def main():
    parser = argparse.ArgumentParser(
        description="Visualize LLM vulnerability detection evaluation results"
    )
    parser.add_argument(
        "--results",
        type=str,
        default="output/evaluation_results.json",
        help="Path to evaluation results JSON file"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="output/visualizations",
        help="Directory to save visualizations and reports"
    )
    
    args = parser.parse_args()
    
    # Load results
    print(f"Loading evaluation results from: {args.results}")
    results = load_json(args.results)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"Output directory: {args.output_dir}")
    
    # Set style
    plt.style.use('seaborn-v0_8-darkgrid')
    sns.set_palette("husl")
    
    # Track generated files
    chart_files = {}
    
    # Generate visualizations for each model
    models_data = results.get('models', {})
    
    for model_name in models_data.keys():
        print(f"\nGenerating visualizations for: {model_name}")
        model_data = models_data[model_name]
        
        chart_files[model_name] = {}
        
        # Confusion matrix
        cm = model_data.get('confusion_matrix', {})
        if cm:
            print("  - Confusion matrix...")
            filename = save_confusion_matrix(cm, model_name, args.output_dir)
            chart_files[model_name]['confusion_matrix'] = filename
        
        # Per-class metrics
        per_class = model_data.get('per_class_metrics', {})
        if per_class:
            print("  - Per-class metrics...")
            filename = plot_per_class_metrics(per_class, model_name, args.output_dir)
            chart_files[model_name]['per_class_metrics'] = filename
        
        # Prediction distribution
        if per_class:
            print("  - Prediction distribution...")
            filename = plot_vulnerability_distribution(per_class, model_name, args.output_dir)
            if filename:
                chart_files[model_name]['prediction_distribution'] = filename
    
    # Model comparison (if multiple models)
    if len(models_data) > 1:
        print("\nGenerating model comparison...")
        filename = plot_model_comparison(models_data, args.output_dir)
        chart_files['model_comparison.png'] = filename
    
    # Generate markdown report
    print("\nGenerating markdown report...")
    md_filepath = generate_markdown_report(results, args.output_dir, chart_files)
    
    print(f"\n{'='*60}")
    print("Visualization Complete!")
    print(f"{'='*60}")
    print(f"Output directory: {os.path.abspath(args.output_dir)}")
    print(f"Markdown report: {os.path.basename(md_filepath)}")
    print(f"Generated {sum(len(v) for v in chart_files.values() if isinstance(v, dict))} charts")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()