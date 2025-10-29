"""
Core Matrix Analysis Module
Provides tools for analyzing traffic matrix properties
Focus: Research validation, not production anomaly detection
"""

import numpy as np
from sklearn.decomposition import NMF, PCA
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from scipy.linalg import svd as scipy_svd
from scipy.spatial.distance import cosine
import pickle


class TrafficMatrixAnalyzer:
    """
    Analyzer for traffic matrix X = AF + N
    Focus on validation rather than prediction
    """

    def __init__(self, normalize=True):
        """
        Args:
            normalize: Whether to normalize features before decomposition
        """
        self.normalize = normalize
        self.scaler = StandardScaler() if normalize else None

    def decompose(self, X, n_components, method='nmf', random_state=42):
        """
        Decompose traffic matrix X

        Args:
            X: numpy array, shape (m, n), traffic matrix
            n_components: int, number of basis (k)
            method: str, 'nmf' or 'pca' or 'svd'

        Returns:
            A: Assignment matrix (m, k)
            F: Feature basis matrix (k, n)
            reconstruction_error: float
        """
        if self.normalize and self.scaler is not None:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = X.copy()

        if method == 'nmf':
            # For NMF, need non-negative data
            if self.normalize:
                temp_scaler = MinMaxScaler()
                X_scaled = temp_scaler.fit_transform(X)

            model = NMF(n_components=n_components, init='nndsvda', random_state=random_state, max_iter=500)
            A = model.fit_transform(X_scaled)
            F = model.components_

        elif method == 'pca':
            model = PCA(n_components=n_components, random_state=random_state)
            A = model.fit_transform(X_scaled)
            F = model.components_

        elif method == 'svd':
            U, s, Vt = scipy_svd(X_scaled, full_matrices=False)
            k = min(n_components, len(s))
            A = U[:, :k] * s[:k]
            F = Vt[:k, :]
        else:
            raise ValueError(f"Unknown method: {method}")

        # Compute reconstruction error
        X_reconstructed = A @ F
        reconstruction_error = np.linalg.norm(X_scaled - X_reconstructed, ord='fro')

        return A, F, reconstruction_error

    def analyze_rank(self, X, max_k=20):
        """
        Analyze effective rank of matrix X using SVD

        Args:
            X: numpy array, shape (m, n)
            max_k: maximum k to test

        Returns:
            dict with:
                - singular_values: array of singular values
                - explained_variance_ratio: cumulative variance explained
                - reconstruction_errors: errors for different k values
                - effective_rank: estimated effective rank (95% variance)
        """
        if self.normalize and self.scaler is not None:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = X.copy()

        # Compute full SVD
        U, s, Vt = scipy_svd(X_scaled, full_matrices=False)

        # Compute explained variance
        total_variance = np.sum(s ** 2)
        explained_var_ratio = np.cumsum(s ** 2) / total_variance

        # Find effective rank (95% variance threshold)
        effective_rank = np.argmax(explained_var_ratio >= 0.95) + 1

        # Compute reconstruction errors for different k
        max_k = min(max_k, len(s))
        reconstruction_errors = []
        for k in range(1, max_k + 1):
            A_k = U[:, :k] * s[:k]
            F_k = Vt[:k, :]
            X_reconstructed = A_k @ F_k
            error = np.linalg.norm(X_scaled - X_reconstructed, ord='fro') / np.linalg.norm(X_scaled, ord='fro')
            reconstruction_errors.append(error)

        return {
            'singular_values': s,
            'explained_variance_ratio': explained_var_ratio,
            'reconstruction_errors': reconstruction_errors,
            'effective_rank': effective_rank
        }

    def compute_stability(self, X_list, n_components, method='nmf'):
        """
        Compute stability of decomposition across multiple matrices

        Args:
            X_list: list of numpy arrays, multiple time windows
            n_components: int, k value
            method: decomposition method

        Returns:
            dict with:
                - F_list: list of feature basis matrices
                - similarity_matrix: pairwise similarity between F matrices
                - mean_similarity: average similarity score
                - std_similarity: stability measure
        """
        F_list = []

        # Decompose each matrix
        for X in X_list:
            _, F, _ = self.decompose(X, n_components, method=method)
            F_list.append(F)

        # Compute pairwise similarity
        n = len(F_list)
        similarity_matrix = np.zeros((n, n))

        for i in range(n):
            for j in range(i+1, n):
                sim = self.compute_basis_similarity(F_list[i], F_list[j], method='cosine')
                similarity_matrix[i, j] = sim
                similarity_matrix[j, i] = sim

        # Set diagonal to 1
        np.fill_diagonal(similarity_matrix, 1.0)

        # Compute statistics
        upper_triangle = similarity_matrix[np.triu_indices(n, k=1)]
        mean_sim = np.mean(upper_triangle)
        std_sim = np.std(upper_triangle)

        return {
            'F_list': F_list,
            'similarity_matrix': similarity_matrix,
            'mean_similarity': mean_sim,
            'std_similarity': std_sim
        }

    def compute_basis_similarity(self, F1, F2, method='cosine'):
        """
        Compute similarity between two feature basis matrices using optimal matching

        Args:
            F1, F2: numpy arrays, shape (k, n)
            method: 'cosine', 'correlation', or 'euclidean'

        Returns:
            similarity: float, similarity score (0-1 for cosine)
        """
        k1, n1 = F1.shape
        k2, n2 = F2.shape

        if k1 != k2:
            # If different k, only compare min(k1, k2) basis vectors
            k = min(k1, k2)
            F1 = F1[:k, :]
            F2 = F2[:k, :]
        else:
            k = k1

        # Compute pairwise similarities between basis vectors
        pairwise_sim = np.zeros((k, k))
        for i in range(k):
            for j in range(k):
                if method == 'cosine':
                    # Cosine similarity: 1 - cosine_distance
                    pairwise_sim[i, j] = 1 - cosine(F1[i, :], F2[j, :])
                elif method == 'correlation':
                    pairwise_sim[i, j] = np.corrcoef(F1[i, :], F2[j, :])[0, 1]
                elif method == 'euclidean':
                    # Convert distance to similarity
                    dist = np.linalg.norm(F1[i, :] - F2[j, :])
                    pairwise_sim[i, j] = 1 / (1 + dist)

        # Find optimal matching (greedy)
        matching_sim = []
        used_j = set()
        for i in range(k):
            # Find best match for basis i from F1
            best_j = None
            best_sim = -np.inf
            for j in range(k):
                if j not in used_j and pairwise_sim[i, j] > best_sim:
                    best_sim = pairwise_sim[i, j]
                    best_j = j
            if best_j is not None:
                matching_sim.append(best_sim)
                used_j.add(best_j)

        # Return average similarity of matched pairs
        return np.mean(matching_sim) if matching_sim else 0.0

    def analyze_feature_importance(self, F, feature_names):
        """
        Analyze which features are most important in the basis

        Args:
            F: numpy array, shape (k, n), feature basis
            feature_names: list of feature names

        Returns:
            dict with:
                - feature_weights: importance of each feature (k x n matrix)
                - top_features: most important features per basis
        """
        k, n = F.shape

        # Normalize each basis vector to get relative importance
        F_normalized = np.abs(F) / (np.abs(F).sum(axis=1, keepdims=True) + 1e-10)

        top_features = []
        for i in range(k):
            # Get top 5 features for this basis
            top_indices = np.argsort(F_normalized[i, :])[-5:][::-1]
            top_feat = [(feature_names[idx], F_normalized[i, idx], F[i, idx])
                        for idx in top_indices]
            top_features.append(top_feat)

        return {
            'feature_weights': F_normalized,
            'top_features': top_features
        }


class FeatureSubsetAnalyzer:
    """
    Analyze decomposition with different feature subsets
    To answer: which features contribute to stable decomposition?
    """

    def __init__(self, feature_names):
        """
        Args:
            feature_names: list of all 14 feature names
        """
        self.feature_names = feature_names

        # Define feature groups based on indices
        # Assuming order: total_packets, total_bytes, tcp_packets, tcp_bytes,
        #                udp_packets, udp_bytes, icmp_packets, icmp_bytes,
        #                other_packets, other_bytes, tcp_syn, tcp_ack, tcp_rst, tcp_fin
        self.feature_groups = {
            'all': list(range(len(feature_names))),
            'packet_counts': [0, 2, 4, 6, 8],  # total, tcp, udp, icmp, other packets
            'byte_counts': [1, 3, 5, 7, 9],    # total, tcp, udp, icmp, other bytes
            'tcp_flags': [10, 11, 12, 13],     # syn, ack, rst, fin
            'protocol_stats': [2, 3, 4, 5, 6, 7, 8, 9],  # protocol packets/bytes
            'tcp_only': [2, 3, 10, 11, 12, 13],  # tcp packets, bytes, flags
            'udp_only': [4, 5],  # udp packets, bytes
        }

    def compare_feature_subsets(self, X, n_components=5):
        """
        Compare decomposition quality with different feature subsets

        Args:
            X: full traffic matrix (m x n)
            n_components: k value

        Returns:
            dict with results for each feature subset
        """
        analyzer = TrafficMatrixAnalyzer()
        results = {}

        for subset_name, indices in self.feature_groups.items():
            X_subset = X[:, indices]

            # Decompose
            A, F, recon_error = analyzer.decompose(X_subset, n_components, method='nmf')

            # Analyze rank
            rank_info = analyzer.analyze_rank(X_subset, max_k=min(15, X_subset.shape[1]))

            results[subset_name] = {
                'reconstruction_error': recon_error,
                'effective_rank': rank_info['effective_rank'],
                'num_features': len(indices)
            }

        return results
