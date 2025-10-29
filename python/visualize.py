"""
可视化模块
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA


def plot_feature_basis(F, feature_names, output_path='feature_basis.png', figsize=(12, 8)):
    """
    可视化特征基矩阵 F
    使用热力图展示每个特征基的特征权重

    参数:
    - F: numpy array, shape (k, n), 特征基矩阵
    - feature_names: list of str, 特征名称
    - output_path: str, 输出文件路径
    - figsize: tuple, 图片大小
    """
    k, n = F.shape

    plt.figure(figsize=figsize)

    # 创建DataFrame便于绘图
    df = pd.DataFrame(F, columns=feature_names)
    df.index = [f'Basis {i}' for i in range(k)]

    # 绘制热力图
    sns.heatmap(df, annot=True, fmt='.3f', cmap='YlOrRd', cbar_kws={'label': 'Weight'})

    plt.title(f'Feature Basis Matrix (k={k}, n={n})', fontsize=14, fontweight='bold')
    plt.xlabel('Features', fontsize=12)
    plt.ylabel('Feature Basis', fontsize=12)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Feature basis heatmap saved to: {output_path}")


def plot_reconstruction_error(errors, timestamps, output_path='reconstruction_error.png', figsize=(12, 6)):
    """
    可视化重构误差随时间的变化

    参数:
    - errors: list or numpy array, 重构误差
    - timestamps: list or numpy array, 时间戳
    - output_path: str, 输出文件路径
    - figsize: tuple, 图片大小
    """
    plt.figure(figsize=figsize)

    plt.plot(timestamps, errors, marker='o', linestyle='-', linewidth=1, markersize=3)

    plt.title('Reconstruction Error Over Time', fontsize=14, fontweight='bold')
    plt.xlabel('Timestamp', fontsize=12)
    plt.ylabel('Mean Reconstruction Error', fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Reconstruction error plot saved to: {output_path}")


def plot_assignment_matrix(A, ip_labels, output_path='assignment.png', figsize=(12, 8), max_ips=50):
    """
    可视化分配矩阵 A
    展示每个IP在各特征基上的权重分布

    参数:
    - A: numpy array, shape (m, k), 分配矩阵
    - ip_labels: list of str, IP地址标签
    - output_path: str, 输出文件路径
    - figsize: tuple, 图片大小
    - max_ips: int, 最多显示的IP数量
    """
    m, k = A.shape

    # 限制显示的IP数量
    if m > max_ips:
        # 选择权重变化最大的IP
        variance = np.var(A, axis=1)
        top_indices = np.argsort(variance)[-max_ips:]
        A = A[top_indices]
        ip_labels = [ip_labels[i] for i in top_indices]
        m = max_ips

    plt.figure(figsize=figsize)

    # 创建DataFrame
    df = pd.DataFrame(A, columns=[f'Basis {i}' for i in range(k)])
    df.index = ip_labels

    # 绘制热力图
    sns.heatmap(df, annot=False, cmap='viridis', cbar_kws={'label': 'Weight'})

    plt.title(f'Assignment Matrix A (showing {m} IPs)', fontsize=14, fontweight='bold')
    plt.xlabel('Feature Basis', fontsize=12)
    plt.ylabel('IP Address', fontsize=12)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Assignment matrix heatmap saved to: {output_path}")


def plot_ip_projection(A, ip_labels, method='pca', output_path='ip_projection.png', figsize=(10, 8)):
    """
    将A投影到2D平面，可视化IP聚类

    参数:
    - A: numpy array, shape (m, k), 分配矩阵
    - ip_labels: list of str, IP地址标签
    - method: str, 降维方法 ('pca')
    - output_path: str, 输出文件路径
    - figsize: tuple, 图片大小
    """
    m, k = A.shape

    if k > 2:
        # 降维到2D
        if method == 'pca':
            pca = PCA(n_components=2)
            A_2d = pca.fit_transform(A)
            explained_var = pca.explained_variance_ratio_
        else:
            raise ValueError(f"Unknown method: {method}")
    else:
        A_2d = A
        explained_var = [1.0, 1.0]

    plt.figure(figsize=figsize)

    plt.scatter(A_2d[:, 0], A_2d[:, 1], alpha=0.6, s=50)

    # 标注一些IP（避免过于拥挤）
    if m < 20:
        for i, label in enumerate(ip_labels):
            plt.annotate(label, (A_2d[i, 0], A_2d[i, 1]),
                        fontsize=8, alpha=0.7)

    plt.title('IP Projection in 2D Space', fontsize=14, fontweight='bold')
    plt.xlabel(f'PC1 ({explained_var[0]*100:.1f}%)', fontsize=12)
    plt.ylabel(f'PC2 ({explained_var[1]*100:.1f}%)', fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"IP projection plot saved to: {output_path}")


def plot_anomaly_detection(errors, threshold, timestamps, output_path='anomaly.png', figsize=(12, 6)):
    """
    可视化异常检测结果

    参数:
    - errors: numpy array, 重构误差
    - threshold: float, 异常阈值
    - timestamps: numpy array, 时间戳
    - output_path: str, 输出文件路径
    - figsize: tuple, 图片大小
    """
    plt.figure(figsize=figsize)

    # 分离正常和异常点
    normal_mask = errors <= threshold
    anomaly_mask = errors > threshold

    plt.scatter(timestamps[normal_mask], errors[normal_mask],
               c='blue', label='Normal', alpha=0.6, s=30)
    plt.scatter(timestamps[anomaly_mask], errors[anomaly_mask],
               c='red', label='Anomaly', alpha=0.8, s=50, marker='x')

    # 绘制阈值线
    plt.axhline(y=threshold, color='red', linestyle='--',
               linewidth=2, label=f'Threshold={threshold:.2f}')

    plt.title('Anomaly Detection Results', fontsize=14, fontweight='bold')
    plt.xlabel('Timestamp', fontsize=12)
    plt.ylabel('Reconstruction Error', fontsize=12)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Anomaly detection plot saved to: {output_path}")


def plot_elbow_curve(k_values, errors, output_path='elbow_curve.png', figsize=(10, 6)):
    """
    绘制肘部曲线用于选择最优k值

    参数:
    - k_values: list, k值列表
    - errors: list, 对应的重构误差
    - output_path: str, 输出文件路径
    - figsize: tuple, 图片大小
    """
    plt.figure(figsize=figsize)

    plt.plot(k_values, errors, marker='o', linestyle='-', linewidth=2, markersize=8)

    plt.title('Elbow Curve for Optimal k Selection', fontsize=14, fontweight='bold')
    plt.xlabel('Number of Components (k)', fontsize=12)
    plt.ylabel('Reconstruction Error', fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"Elbow curve saved to: {output_path}")


if __name__ == '__main__':
    # 测试可视化功能
    print("Visualization module - test mode")

    # 生成测试数据
    np.random.seed(42)
    k, n = 5, 14
    F = np.random.rand(k, n)

    feature_names = [
        'total_packets', 'total_bytes',
        'tcp_packets', 'tcp_bytes',
        'udp_packets', 'udp_bytes',
        'icmp_packets', 'icmp_bytes',
        'other_packets', 'other_bytes',
        'tcp_syn', 'tcp_ack', 'tcp_rst', 'tcp_fin'
    ]

    # 测试特征基可视化
    plot_feature_basis(F, feature_names, 'test_feature_basis.png')

    # 测试重构误差可视化
    timestamps = np.arange(100)
    errors = np.random.rand(100) * 10 + 5
    plot_reconstruction_error(errors, timestamps, 'test_reconstruction_error.png')

    print("\nTest visualizations generated successfully!")
