#!/usr/bin/env python3
"""
Experiment 2: Low-Rank Property Analysis
Research Question: Do behavioral flows exhibit low-rank properties?
"""

import numpy as np
import argparse
from matrix_analysis import TrafficMatrixAnalyzer
from utils import *

def run_rank_experiment(csv_path, max_k=20, output_dir='./results/rank'):
    print("\n" + "=" * 70)
    print(" EXPERIMENT 2: LOW-RANK PROPERTY ANALYSIS")
    print("=" * 70 + "\n")
    
    df, X, feature_names, ip_labels, timestamps = load_csv_data(csv_path)
    print(f"Traffic matrix shape: {X.shape}")
    
    analyzer = TrafficMatrixAnalyzer(normalize=True)
    rank_result = analyzer.analyze_rank(X, max_k=max_k)
    
    print(f"\nEffective rank (95% variance): {rank_result['effective_rank']}")
    print(f"Top 5 singular values: {rank_result['singular_values'][:5]}")
    
    # Save results
    results = {
        'effective_rank': int(rank_result['effective_rank']),
        'singular_values_top10': rank_result['singular_values'][:10].tolist(),
        'reconstruction_errors': rank_result['reconstruction_errors'],
        'matrix_shape': X.shape
    }
    save_results(results, output_dir, 'rank_results')
    
    # Create report
    report_text = f"""
Low-Rank Property Analysis
Matrix shape: {X.shape}
Effective rank (95% variance): {rank_result['effective_rank']}

Top 10 singular values:
{np.array2string(rank_result['singular_values'][:10], precision=2)}

Interpretation:
  - Effective rank < 5: Very low rank, strong structure
  - Effective rank 5-10: Low rank, moderate structure
  - Effective rank > 10: Not low-rank

Conclusion: {"Traffic IS low-rank" if rank_result['effective_rank'] < 10 else "Traffic is NOT low-rank"}
"""
    create_experiment_report(output_dir, 'rank', report_text)
    return results

def main():
    parser = argparse.ArgumentParser(description='Low-Rank Experiments')
    parser.add_argument('csv_path', help='Path to CSV')
    parser.add_argument('--output', default='./results/rank')
    parser.add_argument('--max_k', type=int, default=20)
    args = parser.parse_args()
    
    run_rank_experiment(args.csv_path, args.max_k, args.output)
    print("\nRANK EXPERIMENT COMPLETED\n")

if __name__ == '__main__':
    main()
