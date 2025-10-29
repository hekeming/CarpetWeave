"""
Utility Functions for Traffic Matrix Analysis
"""

import pandas as pd
import numpy as np
import os
import json


def load_csv_data(csv_path):
    """
    Load CSV data and extract feature matrix

    Args:
        csv_path: path to CSV file from C++ extractor

    Returns:
        df: pandas DataFrame
        X: feature matrix (numpy array, shape m x n)
        feature_names: list of feature column names
        ip_labels: list of IP addresses
        timestamps: array of timestamps
    """
    print(f"Loading CSV data from {csv_path}...")

    df = pd.read_csv(csv_path)
    print(f"Total records: {len(df)}")
    print(f"Columns: {df.columns.tolist()}")

    # Feature columns (exclude timestamp and ip)
    feature_cols = [col for col in df.columns if col not in ['timestamp', 'ip']]
    print(f"Feature columns ({len(feature_cols)}): {feature_cols}")

    # Extract feature matrix
    X = df[feature_cols].values
    ip_labels = df['ip'].values
    timestamps = df['timestamp'].values

    return df, X, feature_cols, ip_labels, timestamps


def load_window_matrices(csv_path, window_group_size=10):
    """
    Load CSV and group into time window segments for stability analysis

    Args:
        csv_path: path to CSV file
        window_group_size: how many consecutive windows to group together

    Returns:
        list of window_data dicts with keys:
            - 'timestamp_range': (start_ts, end_ts)
            - 'X': feature matrix for this segment
            - 'ips': IP labels for this segment
            - 'timestamps': individual timestamps
    """
    df, X, feature_names, ip_labels, timestamps = load_csv_data(csv_path)

    # Get unique timestamps
    unique_timestamps = sorted(df['timestamp'].unique())
    print(f"Total unique timestamps: {len(unique_timestamps)}")

    # Group into segments
    segments = []
    for i in range(0, len(unique_timestamps), window_group_size):
        segment_timestamps = unique_timestamps[i:i+window_group_size]
        if len(segment_timestamps) < window_group_size // 2:
            # Skip incomplete segments at the end
            continue

        # Extract rows for this segment
        mask = df['timestamp'].isin(segment_timestamps)
        segment_data = df[mask]

        segment = {
            'timestamp_range': (segment_timestamps[0], segment_timestamps[-1]),
            'X': segment_data[feature_names].values,
            'ips': segment_data['ip'].values,
            'timestamps': segment_data['timestamp'].values,
            'num_windows': len(segment_timestamps)
        }
        segments.append(segment)

    print(f"Created {len(segments)} segments of ~{window_group_size} windows each")
    return segments, feature_names


def save_results(results, output_dir, filename):
    """
    Save experimental results to JSON file

    Args:
        results: dict of results
        output_dir: output directory
        filename: output filename (without extension)
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{filename}.json")

    # Convert numpy arrays to lists for JSON serialization
    def convert_numpy(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: convert_numpy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_numpy(item) for item in obj]
        else:
            return obj

    results_serializable = convert_numpy(results)

    with open(output_path, 'w') as f:
        json.dump(results_serializable, f, indent=2)

    print(f"Results saved to: {output_path}")


def print_summary_table(data_dict, title="Summary"):
    """
    Print a formatted summary table

    Args:
        data_dict: dictionary of {name: value}
        title: table title
    """
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

    max_key_len = max(len(str(k)) for k in data_dict.keys())

    for key, value in data_dict.items():
        if isinstance(value, float):
            print(f"  {key:<{max_key_len}} : {value:.4f}")
        else:
            print(f"  {key:<{max_key_len}} : {value}")

    print("=" * 70 + "\n")


def create_experiment_report(output_dir, experiment_name, summary_text):
    """
    Create a text report for experiment results

    Args:
        output_dir: output directory
        experiment_name: name of experiment
        summary_text: text summary to write
    """
    report_path = os.path.join(output_dir, f"{experiment_name}_report.txt")

    with open(report_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write(f" {experiment_name.upper()} EXPERIMENT REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(summary_text)

    print(f"Report saved to: {report_path}")
