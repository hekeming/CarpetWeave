"""
特征分析脚本
读取C++生成的CSV，进行矩阵分解分析
"""

import pandas as pd
import numpy as np
from matrix_decomposition import FlowMatrixDecomposition, select_optimal_k
import argparse
import os
import sys


def load_csv_data(csv_path):
    """
    加载CSV数据并转换为时间窗口的矩阵列表

    返回:
    - windows: list of dict
      [
        {
          'timestamp': 60.0,
          'ips': ['192.168.1.100', ...],
          'matrix': numpy array (m, n)
        },
        ...
      ]
    - feature_names: list of str, 特征名称列表（除timestamp和ip外）
    """
    print(f"Loading CSV data from {csv_path}...")

    # 读取CSV
    df = pd.read_csv(csv_path)

    print(f"Total records: {len(df)}")
    print(f"Columns: {df.columns.tolist()}")

    # 特征列（排除timestamp和ip）
    feature_cols = [col for col in df.columns if col not in ['timestamp', 'ip']]
    print(f"Feature columns ({len(feature_cols)}): {feature_cols}")

    # 按时间窗口分组
    windows = []
    for timestamp, group in df.groupby('timestamp'):
        window = {
            'timestamp': timestamp,
            'ips': group['ip'].tolist(),
            'matrix': group[feature_cols].values  # shape (m, n)
        }
        windows.append(window)

    print(f"Total windows: {len(windows)}")
    print(f"Average IPs per window: {np.mean([len(w['ips']) for w in windows]):.1f}")

    return windows, feature_cols


def train_decomposition_model(csv_path, n_components=5, output_dir='./results', method='nmf'):
    """
    训练矩阵分解模型

    流程:
    1. 加载所有历史窗口数据
    2. 堆叠成大矩阵用于训练
    3. 拟合分解模型
    4. 保存模型和特征基
    5. 分析每个窗口的重构误差
    """
    print("\n" + "=" * 60)
    print("TRAINING MODE: Matrix Decomposition Model")
    print("=" * 60 + "\n")

    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)

    # 加载数据
    windows, feature_names = load_csv_data(csv_path)

    if len(windows) == 0:
        print("Error: No data found in CSV file.")
        return

    # 堆叠所有窗口的数据用于训练
    all_matrices = [w['matrix'] for w in windows]
    all_ips = [ip for w in windows for ip in w['ips']]
    X_train = np.vstack(all_matrices)

    print(f"\nTraining matrix shape: {X_train.shape}")
    print(f"Total IP-window samples: {X_train.shape[0]}")

    # 训练模型
    print(f"\nTraining {method.upper()} model with {n_components} components...")
    model = FlowMatrixDecomposition(
        n_components=n_components,
        method=method,
        random_state=42
    )
    model.fit(X_train, feature_names=feature_names)

    print("Training completed!")

    # 保存模型
    model_path = os.path.join(output_dir, 'model.pkl')
    model.save(model_path)
    print(f"\nModel saved to: {model_path}")

    # 保存特征基
    F = model.get_feature_basis()
    feature_basis_df = pd.DataFrame(F, columns=feature_names)
    feature_basis_df.index.name = 'basis_idx'
    feature_basis_path = os.path.join(output_dir, 'feature_basis.csv')
    feature_basis_df.to_csv(feature_basis_path)
    print(f"Feature basis saved to: {feature_basis_path}")

    # 分析特征基
    print("\n" + "-" * 60)
    print("FEATURE BASIS ANALYSIS")
    print("-" * 60)

    for i in range(n_components):
        explanation = model.explain_feature_basis(i, top_k=5)
        print(f"\nFeature Basis {i}:")
        for feat in explanation['features']:
            print(f"  {feat['name']}: {feat['weight']:.4f}")

    # 计算重构误差
    print("\n" + "-" * 60)
    print("RECONSTRUCTION ERROR ANALYSIS")
    print("-" * 60)

    A_train = model.transform(X_train)
    errors, total_error = model.compute_reconstruction_error(X_train, A_train)

    print(f"\nTotal reconstruction error: {total_error:.2f}")
    print(f"Mean error per sample: {np.mean(errors):.2f}")
    print(f"Std error per sample: {np.std(errors):.2f}")
    print(f"Max error: {np.max(errors):.2f}")
    print(f"Min error: {np.min(errors):.2f}")

    # 保存重构误差
    error_df = pd.DataFrame({
        'ip': all_ips,
        'reconstruction_error': errors
    })
    error_path = os.path.join(output_dir, 'reconstruction_errors.csv')
    error_df.to_csv(error_path, index=False)
    print(f"\nReconstruction errors saved to: {error_path}")

    # 按窗口分析误差
    window_errors = []
    start_idx = 0
    for window in windows:
        m = window['matrix'].shape[0]
        window_mean_error = np.mean(errors[start_idx:start_idx + m])
        window_errors.append({
            'timestamp': window['timestamp'],
            'num_ips': m,
            'mean_error': window_mean_error
        })
        start_idx += m

    window_error_df = pd.DataFrame(window_errors)
    window_error_path = os.path.join(output_dir, 'window_errors.csv')
    window_error_df.to_csv(window_error_path, index=False)
    print(f"Window-level errors saved to: {window_error_path}")

    # 异常检测阈值建议
    threshold_95 = np.percentile(errors, 95)
    threshold_99 = np.percentile(errors, 99)
    threshold_3sigma = np.mean(errors) + 3 * np.std(errors)

    print("\n" + "-" * 60)
    print("ANOMALY DETECTION THRESHOLDS (Recommendations)")
    print("-" * 60)
    print(f"95th percentile: {threshold_95:.2f}")
    print(f"99th percentile: {threshold_99:.2f}")
    print(f"Mean + 3*Std: {threshold_3sigma:.2f}")

    # 可视化（如果matplotlib可用）
    try:
        import visualize
        print("\n" + "-" * 60)
        print("GENERATING VISUALIZATIONS")
        print("-" * 60)

        # 特征基热力图
        vis_path = os.path.join(output_dir, 'feature_basis.png')
        visualize.plot_feature_basis(F, feature_names, vis_path)
        print(f"Feature basis heatmap: {vis_path}")

        # 重构误差时间序列
        vis_path = os.path.join(output_dir, 'reconstruction_error.png')
        timestamps = [w['timestamp'] for w in window_errors]
        mean_errors = [w['mean_error'] for w in window_errors]
        visualize.plot_reconstruction_error(mean_errors, timestamps, vis_path)
        print(f"Reconstruction error plot: {vis_path}")

    except ImportError:
        print("\nWarning: matplotlib not available, skipping visualization.")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 60 + "\n")


def realtime_detection(csv_path, model_path, threshold=None, percentile=95):
    """
    实时检测模式

    流程:
    1. 加载预训练的模型
    2. 逐窗口读取数据
    3. 计算 A 和重构误差
    4. 检测异常
    5. 输出报告
    """
    print("\n" + "=" * 60)
    print("DETECTION MODE: Anomaly Detection")
    print("=" * 60 + "\n")

    # 加载模型
    print(f"Loading model from {model_path}...")
    model = FlowMatrixDecomposition.load(model_path)
    print(f"Model loaded: {model.method.upper()} with {model.n_components} components")

    # 加载数据
    windows, feature_names = load_csv_data(csv_path)

    if len(windows) == 0:
        print("Error: No data found in CSV file.")
        return

    # 逐窗口检测
    print("\n" + "-" * 60)
    print("WINDOW-BY-WINDOW ANOMALY DETECTION")
    print("-" * 60)

    total_ips = 0
    total_anomalies = 0

    for i, window in enumerate(windows):
        X_window = window['matrix']
        ip_labels = window['ips']

        # 检测异常
        anomalous_ips = model.get_anomalous_ips(
            X_window,
            ip_labels,
            threshold=threshold,
            percentile=percentile
        )

        total_ips += len(ip_labels)
        total_anomalies += len(anomalous_ips)

        # 输出结果
        if len(anomalous_ips) > 0:
            print(f"\nWindow [{window['timestamp']:.6f}]:")
            print(f"  Total IPs: {len(ip_labels)}")
            print(f"  Anomalous IPs: {len(anomalous_ips)}")
            print(f"  Threshold: {anomalous_ips[0]['threshold']:.2f}")

            for anom in anomalous_ips[:10]:  # 最多显示10个异常IP
                print(f"    - {anom['ip']}: error={anom['error']:.2f}")

            if len(anomalous_ips) > 10:
                print(f"    ... and {len(anomalous_ips) - 10} more")

    # 总结
    print("\n" + "=" * 60)
    print("DETECTION SUMMARY")
    print("=" * 60)
    print(f"Total windows: {len(windows)}")
    print(f"Total IPs analyzed: {total_ips}")
    print(f"Anomalous IPs detected: {total_anomalies} ({100*total_anomalies/total_ips:.1f}%)")
    print("=" * 60 + "\n")


def analyze_feature_basis(model, feature_names):
    """
    分析特征基的语义
    输出每个特征基的主要特征
    """
    pass  # 已在train_decomposition_model中实现


def main():
    parser = argparse.ArgumentParser(
        description='IPv4 Flow Matrix Decomposition Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train mode
  python analyze_features.py data.csv --mode train --n_components 5

  # Detection mode
  python analyze_features.py new_data.csv --mode detect --model results/model.pkl
        """
    )

    parser.add_argument('csv_path', help='Path to CSV file')
    parser.add_argument('--mode', choices=['train', 'detect'], default='train',
                        help='Operation mode (default: train)')
    parser.add_argument('--n_components', type=int, default=5,
                        help='Number of feature basis components (default: 5)')
    parser.add_argument('--output', default='./results',
                        help='Output directory (default: ./results)')
    parser.add_argument('--method', choices=['nmf', 'pca'], default='nmf',
                        help='Decomposition method (default: nmf)')
    parser.add_argument('--model', help='Path to trained model (for detect mode)')
    parser.add_argument('--threshold', type=float, default=None,
                        help='Anomaly detection threshold (default: auto)')
    parser.add_argument('--percentile', type=float, default=95,
                        help='Percentile for auto threshold (default: 95)')

    args = parser.parse_args()

    # 检查CSV文件
    if not os.path.exists(args.csv_path):
        print(f"Error: CSV file not found: {args.csv_path}")
        sys.exit(1)

    if args.mode == 'train':
        train_decomposition_model(
            args.csv_path,
            n_components=args.n_components,
            output_dir=args.output,
            method=args.method
        )
    else:  # detect mode
        model_path = args.model or os.path.join(args.output, 'model.pkl')
        if not os.path.exists(model_path):
            print(f"Error: Model file not found: {model_path}")
            print("Please train a model first using --mode train")
            sys.exit(1)

        realtime_detection(
            args.csv_path,
            model_path,
            threshold=args.threshold,
            percentile=args.percentile
        )


if __name__ == '__main__':
    main()
