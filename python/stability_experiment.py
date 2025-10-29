"""
Experiment 1: Stability of Behavioral Flow Decomposition
Research Question: Does stable decomposition pattern exist?
"""

import numpy as np
import argparse
from matrix_analysis import TrafficMatrixAnalyzer, FeatureSubsetAnalyzer
from utils import *

def run_stability_experiment(csv_path, k_values=[3, 5, 7, 10], output_dir='./results/stability'):
    """
    Main stability experiment: Test decomposition stability across time
    """
    print("\n" + "=" * 70)
    print(" EXPERIMENT 1: TEMPORAL STABILITY OF DECOMPOSITION")
    print("=" * 70 + "\n")
    
    # Load data grouped by time segments
    segments, feature_names = load_window_matrices(csv_path, window_group_size=10)
    
    if len(segments) < 2:
        print("Error: Need at least 2 time segments for stability analysis")
        return
    
    analyzer = TrafficMatrixAnalyzer(normalize=True)
    results = {}
    
    for k in k_values:
        print(f"\n--- Testing k={k} ---")
        
        # Extract matrices from segments
        X_list = [seg['X'] for seg in segments]
        
        # Compute stability
        stability_result = analyzer.compute_stability(X_list, n_components=k, method='nmf')
        
        results[f'k={k}'] = {
            'mean_similarity': float(stability_result['mean_similarity']),
            'std_similarity': float(stability_result['std_similarity']),
            'num_segments': len(segments)
        }
        
        print(f"  Mean similarity: {stability_result['mean_similarity']:.4f} ± {stability_result['std_similarity']:.4f}")
    
    # Save results
    save_results(results, output_dir, 'stability_results')
    
    # Print summary
    summary = {f"k={k}": f"{results[f'k={k}']['mean_similarity']:.4f} ± {results[f'k={k}']['std_similarity']:.4f}" 
               for k in k_values}
    print_summary_table(summary, "Stability Scores by k")
    
    # Create report
    report_text = f"""
Temporal Stability Analysis
Number of segments: {len(segments)}
Windows per segment: ~10

Results:
"""
    for k in k_values:
        r = results[f'k={k}']
        report_text += f"  k={k}: {r['mean_similarity']:.4f} ± {r['std_similarity']:.4f}\n"
    
    report_text += f"""
Interpretation:
  - Mean similarity > 0.8: Very stable behavioral patterns
  - Mean similarity 0.6-0.8: Moderately stable
  - Mean similarity < 0.6: Unstable/dynamic traffic

Conclusion: {"Stable behavioral flows exist" if max(results[f'k={k}']['mean_similarity'] for k in k_values) > 0.7 else "Traffic patterns are highly dynamic"}
"""
    
    create_experiment_report(output_dir, 'stability', report_text)
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Stability Experiments')
    parser.add_argument('csv_path', help='Path to traffic features CSV')
    parser.add_argument('--output', default='./results/stability', help='Output directory')
    parser.add_argument('--k_values', nargs='+', type=int, default=[3, 5, 7, 10])
    args = parser.parse_args()
    
    run_stability_experiment(args.csv_path, args.k_values, args.output)
    print("\nSTABILITY EXPERIMENT COMPLETED\n")

if __name__ == '__main__':
    main()
