# IP Flow Matrix Decomposition Analysis

基于矩阵分解的网络流量特征分析与异常检测系统。

## 算法原理

### 矩阵分解模型

```
X ≈ A * F

其中:
- X ∈ R^(m×n): IP流量特征矩阵
  - m: IP数量
  - n: 特征维度（14个特征）

- F ∈ R^(k×n): 特征基矩阵（Feature basis matrix）
  - k: 特征基的数量（通常3-10）
  - 每一行是一个基础流量模式

- A ∈ R^(m×k): 分配策略矩阵（Assignment matrix）
  - A[i,j] 表示第i个IP在第j个特征基上的权重
  - 描述每个IP的流量如何由基础模式组合而成
```

### 特征说明

14维特征向量（从CSV文件提取）：

| 特征名称 | 说明 |
|---------|------|
| total_packets | 总包数 |
| total_bytes | 总字节数 |
| tcp_packets | TCP包数 |
| tcp_bytes | TCP字节数 |
| udp_packets | UDP包数 |
| udp_bytes | UDP字节数 |
| icmp_packets | ICMP包数 |
| icmp_bytes | ICMP字节数 |
| other_packets | 其他协议包数 |
| other_bytes | 其他协议字节数 |
| tcp_syn | TCP SYN标志数 |
| tcp_ack | TCP ACK标志数 |
| tcp_rst | TCP RST标志数 |
| tcp_fin | TCP FIN标志数 |

## 安装依赖

```bash
cd python
pip install -r requirements.txt
```

依赖包：
- numpy: 数值计算
- pandas: 数据处理
- scikit-learn: 机器学习算法（NMF/PCA）
- matplotlib: 可视化
- seaborn: 高级可视化
- scipy: 科学计算

## 使用方法

### 1. 训练模式

从历史流量数据学习特征基 F：

```bash
python analyze_features.py ../cpp/build/features.csv --mode train --n_components 5 --output ./results
```

参数说明：
- `csv_path`: C++生成的特征CSV文件路径
- `--mode train`: 训练模式
- `--n_components 5`: 特征基数量k=5
- `--output ./results`: 输出目录
- `--method nmf`: 分解方法（nmf或pca，默认nmf）

输出文件：
- `results/model.pkl`: 训练好的模型（可用于后续检测）
- `results/feature_basis.csv`: 特征基矩阵F
- `results/reconstruction_errors.csv`: 所有样本的重构误差
- `results/window_errors.csv`: 每个时间窗口的平均误差
- `results/feature_basis.png`: 特征基热力图
- `results/reconstruction_error.png`: 误差时间序列图

### 2. 检测模式

使用训练好的模型检测异常：

```bash
python analyze_features.py ../cpp/build/features.csv --mode detect --model ./results/model.pkl
```

参数说明：
- `--mode detect`: 检测模式
- `--model`: 训练好的模型路径
- `--threshold`: 异常阈值（可选，默认自动计算）
- `--percentile 95`: 百分位数阈值（默认95%）

输出：
- 逐窗口异常检测报告
- 异常IP列表及其重构误差
- 异常统计摘要

### 3. 可视化测试

```bash
python visualize.py
```

生成测试可视化图片验证功能。

## 完整工作流程

### 步骤1：提取流量特征（C++）

```bash
cd cpp/build
./ipflow_extractor ../../data/seq_10.pcap ../../data/stats.json
```

生成 `features.csv`。

### 步骤2：训练矩阵分解模型（Python）

```bash
cd ../../python
python analyze_features.py ../cpp/build/features.csv --mode train --n_components 5
```

### 步骤3：分析结果

查看特征基解释：
```bash
cat results/feature_basis.csv
```

查看可视化：
```bash
ls results/*.png
```

### 步骤4：实时检测（可选）

对新流量数据进行异常检测：
```bash
# 先用C++提取新数据的特征
cd cpp/build
./ipflow_extractor ../../data/new_traffic.pcap ../../data/stats.json

# 然后用训练好的模型检测
cd ../../python
python analyze_features.py ../cpp/build/features.csv --mode detect
```

## 算法说明

### 矩阵分解方法

#### NMF（非负矩阵分解）- 推荐

- **优点**：
  - 结果可解释性强（A和F都是非负的）
  - 特别适合流量数据（包数和字节数都是非负的）
  - 特征基可以理解为"流量模式"

- **适用场景**：
  - 流量模式识别
  - 异常检测
  - 用户行为分析

#### PCA（主成分分析）

- **优点**：
  - 计算快速
  - 最大化方差保留

- **缺点**：
  - 可能产生负值，解释性较差

### 特征基数量选择

k的选择策略：

1. **肘部法则**：绘制重构误差vs k的曲线，选择"肘点"
2. **领域知识**：根据已知的流量模式数量
3. **交叉验证**：选择验证误差最小的k

推荐范围：**k = 3 ~ 10**

常见k值含义：
- k=3: 基本模式（正常流量、大流量、攻击流量）
- k=5: 细分模式（Web、DNS、文件传输、扫描、DDoS）
- k=10: 详细模式（多种应用和攻击类型）

### 异常检测方法

#### 重构误差异常检测

**原理**：
1. 训练阶段：用正常流量训练模型，学习正常模式的特征基F
2. 检测阶段：新流量如果重构误差大，说明不符合正常模式
3. 判断标准：误差 > 阈值 → 异常

**阈值选择**：
- **95th percentile**: 假设5%的训练数据可能是异常
- **99th percentile**: 更保守，降低误报
- **Mean + 3σ**: 假设误差服从正态分布

## 输出示例

### 特征基解释

```
Feature Basis 0:
  tcp_packets: 0.8532
  tcp_bytes: 0.8124
  tcp_ack: 0.9012
  total_packets: 0.7821
  total_bytes: 0.7654

Interpretation: High TCP traffic with many ACK packets (normal web traffic)

Feature Basis 1:
  udp_packets: 0.9234
  udp_bytes: 0.8765
  total_packets: 0.6543
  total_bytes: 0.6123
  tcp_packets: 0.1234

Interpretation: UDP-dominated traffic (DNS/Streaming)

Feature Basis 2:
  tcp_syn: 0.9456
  tcp_packets: 0.8901
  total_packets: 0.8234
  tcp_bytes: 0.3456
  total_bytes: 0.3123

Interpretation: High SYN packets with small bytes (potential port scanning)
```

### 异常检测报告

```
Window [1730264404.223618]:
  Total IPs: 229
  Anomalous IPs: 3
  Threshold: 15.23
    - 192.168.1.100: error=25.41 (high UDP activity)
    - 10.0.0.5: error=18.92 (unusual packet size distribution)
    - 172.16.0.10: error=16.54 (high SYN rate)
```

## 高级功能

### 选择最优k值

```python
from matrix_decomposition import select_optimal_k
import pandas as pd
import numpy as np

# 加载数据
df = pd.read_csv('features.csv')
feature_cols = [col for col in df.columns if col not in ['timestamp', 'ip']]
X = df[feature_cols].values

# 测试不同的k值
k_values, errors, optimal_k = select_optimal_k(X, k_range=range(2, 11))

print(f"Optimal k: {optimal_k}")
```

### 自定义阈值

```python
from matrix_decomposition import FlowMatrixDecomposition

# 加载模型
model = FlowMatrixDecomposition.load('results/model.pkl')

# 使用自定义阈值检测
threshold = 20.0
is_anomaly, errors, _ = model.detect_anomaly(X_new, threshold=threshold)
```

### 分析异常原因

```python
# 对于异常样本，查看其特征基权重
A_anomaly = model.transform(X_anomaly)

# 找出权重最大的特征基
dominant_basis = np.argmax(A_anomaly, axis=1)

# 查看该特征基的含义
for i in range(model.n_components):
    explanation = model.explain_feature_basis(i)
    print(f"Basis {i}: {explanation}")
```

## 常见问题

### Q: 如何选择合适的window_size和slide_step？

A:
- **window_size**: 取决于分析需求
  - 短期异常检测：1-5秒
  - 流量模式分析：10-60秒
  - 长期趋势：60秒以上

- **slide_step**: 取决于检测粒度
  - 实时检测：slide_step = window_size（无重叠）
  - 平滑分析：slide_step < window_size（有重叠）

### Q: 训练数据应该包含多少窗口？

A:
- 最少：100个窗口
- 推荐：1000+个窗口
- 原则：覆盖各种正常流量模式

### Q: 如何处理训练集中的异常数据？

A:
1. 清洗：先用简单规则过滤明显异常
2. 鲁棒训练：NMF对少量异常有一定鲁棒性
3. 迭代：训练后检测异常→移除→重新训练

### Q: 模型需要多久更新一次？

A:
- 流量模式稳定：每周更新
- 流量模式多变：每天更新
- 策略：增量更新 vs 完全重训

## 性能说明

- **训练时间**: O(m * n * k * iterations)
  - 1000个样本，k=5: < 1秒
  - 10000个样本，k=5: < 10秒

- **检测时间**: O(m * n * k)
  - 实时检测单窗口: < 0.01秒

- **内存占用**: O(m * n + k * n)
  - 模型大小: < 1MB

## 参考文献

1. Lee, D. D., & Seung, H. S. (2001). Algorithms for non-negative matrix factorization.
2. Lakhina, A., et al. (2005). Structural analysis of network traffic flows.
3. Xu, K., et al. (2006). Behavior analysis of internet traffic via bipartite graphs and one-mode projections.

## 许可证

本项目供学习和研究使用。
