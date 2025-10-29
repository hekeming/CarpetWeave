"""
矩阵分解核心算法模块
实现 X = AF + N 的稳定分解
"""

import numpy as np
from sklearn.decomposition import NMF, PCA
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from scipy.optimize import nnls
import pickle


class FlowMatrixDecomposition:
    """
    流量矩阵分解类
    支持多种分解方法：NMF, PCA, 自定义优化

    模型: X ≈ A * F
    其中:
    - X (m x n): IP流量特征矩阵
    - F (k x n): 特征基矩阵（Feature basis matrix）
    - A (m x k): 分配策略矩阵（Assignment matrix）
    """

    def __init__(self, n_components=5, method='nmf', random_state=42):
        """
        参数:
        - n_components: 特征基数量 k
        - method: 分解方法 ('nmf', 'pca', 'custom')
        - random_state: 随机种子
        """
        self.n_components = n_components
        self.method = method
        self.random_state = random_state

        # 模型组件
        self.model = None
        self.scaler = None
        self.F = None  # 特征基矩阵 (k x n)

        # 训练统计
        self.train_errors = []
        self.feature_names = None

        self._initialize_model()

    def _initialize_model(self):
        """初始化分解模型"""
        if self.method == 'nmf':
            self.model = NMF(
                n_components=self.n_components,
                init='nndsvda',  # 更稳定的初始化方法
                max_iter=500,
                random_state=self.random_state,
                alpha_W=0.01,  # L1正则化
                alpha_H=0.01
            )
            self.scaler = MinMaxScaler()  # NMF需要非负数据
        elif self.method == 'pca':
            self.model = PCA(
                n_components=self.n_components,
                random_state=self.random_state
            )
            self.scaler = StandardScaler()
        else:
            raise ValueError(f"Unknown method: {self.method}")

    def fit(self, X, feature_names=None):
        """
        训练阶段：从历史数据学习特征基 F

        参数:
        - X: numpy array, shape (m, n), 多个窗口的IP流量矩阵堆叠
        - feature_names: list of str, 特征名称列表

        返回:
        - self
        """
        if feature_names is not None:
            self.feature_names = feature_names

        # 数据预处理
        X_scaled = self.scaler.fit_transform(X)

        # 训练模型
        if self.method == 'nmf':
            # NMF: X ≈ WH, 这里 W=A, H=F
            self.model.fit(X_scaled)
            self.F = self.model.components_  # shape (k, n)
        elif self.method == 'pca':
            # PCA: X ≈ T * P^T, 这里 T=A, P^T=F
            self.model.fit(X_scaled)
            self.F = self.model.components_  # shape (k, n)

        # 计算训练误差
        A_train = self.model.transform(X_scaled)
        X_reconstructed = A_train @ self.F
        self.train_errors = np.linalg.norm(X_scaled - X_reconstructed, axis=1)

        return self

    def transform(self, X):
        """
        推理阶段：给定新的X，计算分配矩阵A

        参数:
        - X: numpy array, shape (m, n), 单个或多个窗口的IP流量矩阵

        返回:
        - A: numpy array, shape (m, k), 分配策略矩阵
        """
        if self.model is None or self.F is None:
            raise RuntimeError("Model not fitted. Call fit() first.")

        # 数据预处理
        X_scaled = self.scaler.transform(X)

        # 计算A
        A = self.model.transform(X_scaled)

        return A

    def fit_transform(self, X, feature_names=None):
        """训练并转换"""
        self.fit(X, feature_names)
        return self.transform(X)

    def reconstruct(self, A):
        """
        重构矩阵：X_hat = A * F

        参数:
        - A: numpy array, shape (m, k)

        返回:
        - X_hat: numpy array, shape (m, n), 重构的流量矩阵（归一化后的）
        """
        if self.F is None:
            raise RuntimeError("Model not fitted. Call fit() first.")

        X_reconstructed = A @ self.F
        return X_reconstructed

    def inverse_transform(self, X_scaled):
        """将归一化后的数据转换回原始尺度"""
        return self.scaler.inverse_transform(X_scaled)

    def get_feature_basis(self):
        """
        获取特征基矩阵 F

        返回:
        - F: numpy array, shape (k, n)
        """
        return self.F

    def compute_reconstruction_error(self, X, A=None):
        """
        计算重构误差：||X - AF||_F (Frobenius范数)

        参数:
        - X: numpy array, shape (m, n), 原始数据
        - A: numpy array, shape (m, k), 如果为None则自动计算

        返回:
        - errors: numpy array, shape (m,), 每个样本的重构误差
        - total_error: float, 总体重构误差
        """
        X_scaled = self.scaler.transform(X)

        if A is None:
            A = self.transform(X)

        X_reconstructed = self.reconstruct(A)

        # 计算每个样本的误差
        errors = np.linalg.norm(X_scaled - X_reconstructed, axis=1)
        total_error = np.linalg.norm(X_scaled - X_reconstructed, ord='fro')

        return errors, total_error

    def detect_anomaly(self, X, threshold=None, percentile=95):
        """
        异常检测：计算重构误差，超过阈值则认为是异常

        参数:
        - X: numpy array, shape (m, n), 待检测的流量矩阵
        - threshold: float, 异常阈值（如果为None则自动计算）
        - percentile: float, 百分位数阈值（当threshold为None时使用）

        返回:
        - is_anomaly: numpy array (m,), 布尔数组指示是否异常
        - errors: numpy array (m,), 每个样本的重构误差
        - threshold: float, 使用的阈值
        """
        errors, _ = self.compute_reconstruction_error(X)

        # 自动计算阈值
        if threshold is None:
            if len(self.train_errors) > 0:
                # 使用训练集误差的百分位数
                threshold = np.percentile(self.train_errors, percentile)
            else:
                # 使用当前数据的百分位数
                threshold = np.percentile(errors, percentile)

        is_anomaly = errors > threshold

        return is_anomaly, errors, threshold

    def get_anomalous_ips(self, X, ip_labels, threshold=None, percentile=95):
        """
        获取异常IP列表

        参数:
        - X: numpy array, shape (m, n)
        - ip_labels: list of str, IP地址标签
        - threshold: float, 异常阈值
        - percentile: float, 百分位数阈值

        返回:
        - anomalous_ips: list of dict, 异常IP及其误差
        """
        is_anomaly, errors, used_threshold = self.detect_anomaly(X, threshold, percentile)

        anomalous_ips = []
        for i, (is_anom, error) in enumerate(zip(is_anomaly, errors)):
            if is_anom:
                anomalous_ips.append({
                    'ip': ip_labels[i],
                    'error': error,
                    'threshold': used_threshold
                })

        return anomalous_ips

    def explain_feature_basis(self, basis_idx, top_k=5):
        """
        解释特征基的语义

        参数:
        - basis_idx: int, 特征基索引 (0 to k-1)
        - top_k: int, 返回权重最高的前k个特征

        返回:
        - explanation: dict, 包含特征名称和权重
        """
        if self.F is None:
            raise RuntimeError("Model not fitted.")

        if basis_idx >= self.n_components:
            raise ValueError(f"basis_idx must be < {self.n_components}")

        basis_vector = self.F[basis_idx]

        # 找出权重最大的特征
        top_indices = np.argsort(np.abs(basis_vector))[-top_k:][::-1]

        explanation = {
            'basis_idx': basis_idx,
            'features': []
        }

        for idx in top_indices:
            feature_name = self.feature_names[idx] if self.feature_names else f"Feature_{idx}"
            explanation['features'].append({
                'name': feature_name,
                'weight': basis_vector[idx]
            })

        return explanation

    def save(self, filepath):
        """保存模型到文件"""
        model_data = {
            'n_components': self.n_components,
            'method': self.method,
            'random_state': self.random_state,
            'model': self.model,
            'scaler': self.scaler,
            'F': self.F,
            'train_errors': self.train_errors,
            'feature_names': self.feature_names
        }

        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

    @classmethod
    def load(cls, filepath):
        """从文件加载模型"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)

        # 创建实例
        instance = cls(
            n_components=model_data['n_components'],
            method=model_data['method'],
            random_state=model_data['random_state']
        )

        # 恢复状态
        instance.model = model_data['model']
        instance.scaler = model_data['scaler']
        instance.F = model_data['F']
        instance.train_errors = model_data['train_errors']
        instance.feature_names = model_data['feature_names']

        return instance


def select_optimal_k(X, k_range=range(2, 11), method='nmf', random_state=42):
    """
    使用肘部法则选择最优的k值

    参数:
    - X: numpy array, shape (m, n)
    - k_range: range or list, k值的范围
    - method: str, 分解方法
    - random_state: int, 随机种子

    返回:
    - k_values: list, 测试的k值
    - errors: list, 对应的重构误差
    - optimal_k: int, 推荐的k值（肘点）
    """
    k_values = list(k_range)
    errors = []

    for k in k_values:
        model = FlowMatrixDecomposition(
            n_components=k,
            method=method,
            random_state=random_state
        )
        model.fit(X)
        _, total_error = model.compute_reconstruction_error(X)
        errors.append(total_error)

    # 简单的肘点检测：寻找误差下降最快的点
    if len(errors) > 2:
        diffs = np.diff(errors)
        optimal_idx = np.argmax(np.abs(diffs)) + 1
        optimal_k = k_values[optimal_idx] if optimal_idx < len(k_values) else k_values[-1]
    else:
        optimal_k = k_values[0]

    return k_values, errors, optimal_k
