# CarpetWeave

**Address-to-Behavior Traffic Decomposition for Carpet Bombing DDoS Detection**

CarpetWeave reveals the hidden behavioral structure of network traffic by decomposing observed IP-level flows into latent **behavior flows** using matrix factorization.
This enables accurate detection of **Carpet Bombing DDoS attacks**, where attackers distribute traffic across many IPs to evade traditional per-IP detection.

---

## ✨ Project Status

**Version 2.0 - Fully Implemented**

- ✅ **PCAP → Feature Matrix Pipeline (C++)**: Complete sliding-window feature extraction from PCAP files
- ✅ **Behavior Decomposition (Python)**: NMF-based matrix decomposition (X ≈ A*F) for behavior analysis
- ✅ **Attack Detection**: Anomaly detection based on reconstruction error
- ✅ **Visualization**: Feature basis heatmaps, time series plots, anomaly visualization

---

## 🚀 Quick Start

### 1. Extract Features from PCAP

```bash
cd cpp/build
./ipflow_extractor ../../data/seq_10.pcap ../../data/stats.json
```

Generates **features.csv** with 14-dimensional feature vectors per IP per time window.

### 2. Train Behavior Model

```bash
cd ../../python
python analyze_features.py ../cpp/build/features.csv --mode train --n_components 5
```

Learns **feature basis matrix F** representing 5 latent behavior patterns.

### 3. Detect Anomalies

```bash
python analyze_features.py ../cpp/build/features.csv --mode detect
```

Identifies IPs with unusual behavior based on reconstruction error.

---

## 📊 System Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌────────────────────┐
│  PCAP Files     │ ───> │  C++ Extractor   │ ───> │  CSV Features      │
│  (seq_10.pcap)  │      │  (ipflow_extractor)│     │  14-dim vectors   │
└─────────────────┘      └──────────────────┘      └────────────────────┘
                                                              │
                                                              v
                         ┌──────────────────────────────────────────┐
                         │     Python Analysis Module               │
                         │  ┌────────────────────────────────────┐  │
                         │  │  Matrix Decomposition: X ≈ A * F  │  │
                         │  │  - Learn behavior basis F         │  │
                         │  │  - Compute assignment matrix A    │  │
                         │  │  - Detect anomalies               │  │
                         │  └────────────────────────────────────┘  │
                         └──────────────────────────────────────────┘
                                           │
                                           v
                         ┌────────────────────────────────────┐
                         │  Detection Results                 │
                         │  - Anomalous IPs                   │
                         │  - Behavior patterns               │
                         │  - Visualizations                  │
                         └────────────────────────────────────┘
```

---

## 📂 Repository Structure

```
CarpetWeave/
├── cpp/                          # C++ Feature Extractor (Implemented)
│   ├── include/
│   │   ├── pcap_reader.hpp       # PCAP file parser
│   │   ├── sliding_window.hpp    # Time-based sliding window
│   │   ├── feature_extractor.hpp # Protocol-based feature extraction
│   │   └── csv_writer.hpp        # CSV output
│   ├── src/
│   │   ├── pcap_reader.cpp
│   │   ├── sliding_window.cpp
│   │   ├── feature_extractor.cpp
│   │   ├── csv_writer.cpp
│   │   └── main.cpp
│   ├── CMakeLists.txt
│   └── README.md
├── python/                       # Python Analysis Module (Implemented)
│   ├── matrix_decomposition.py   # Core NMF/PCA implementation
│   ├── analyze_features.py       # Main analysis script
│   ├── visualize.py              # Visualization tools
│   ├── requirements.txt
│   └── README.md
├── data/                         # Data & Configuration
│   ├── seq_10.pcap              # Test PCAP file (99MB)
│   └── stats.json               # Configuration file
└── README.md                     # This file
```

### Implementation Status

| Component | Status | Description |
|-----------|--------|-------------|
| **C++ Extractor** | ✅ Complete | High-performance PCAP parser with sliding window analysis |
| **Feature Extraction** | ✅ Complete | Protocol statistics (TCP/UDP/ICMP), TCP flags |
| **Python Decomposition** | ✅ Complete | NMF/PCA-based matrix factorization |
| **Anomaly Detection** | ✅ Complete | Reconstruction error-based detection |
| **Visualization** | ✅ Complete | Heatmaps, time series, projections |

---

## 🎯 Key Features

### C++ Feature Extractor
- **Sliding Window Analysis**: Configurable window size (default 2s) and slide step (default 1s)
- **Protocol Statistics**: Per-protocol packet count and byte count (TCP/UDP/ICMP/Other)
- **TCP Flag Analysis**: SYN/ACK/RST/FIN counting for anomaly patterns
- **IP Filtering**: Target-specific analysis based on configuration
- **Performance**: Processes ~1.3M packets/minute

### Python Behavior Decomposition
- **Matrix Factorization**: X ≈ A * F decomposition using NMF or PCA
- **Feature Basis Learning**: Discovers k latent behavior patterns
- **Anomaly Detection**: Identifies outliers based on reconstruction error
- **Interpretability**: Explains behavior patterns with feature weights
- **Visualization**: Feature basis heatmaps, error plots, IP projections

---

## 📖 Detailed Documentation

- **C++ Documentation**: [cpp/README.md](cpp/README.md)
- **Python Documentation**: [python/README.md](python/README.md)

---

## 🔬 Methodology

### Matrix Decomposition Model

```
X ≈ A * F

Where:
- X ∈ R^(m×n): IP feature matrix (m IPs × 14 features)
- F ∈ R^(k×n): Feature basis matrix (k behavior patterns × 14 features)
- A ∈ R^(m×k): Assignment matrix (m IPs × k behaviors)
```

### 14-Dimensional Feature Vector

| Feature | Description |
|---------|-------------|
| `total_packets` | Total packet count |
| `total_bytes` | Total byte count |
| `tcp_packets`, `tcp_bytes` | TCP statistics |
| `udp_packets`, `udp_bytes` | UDP statistics |
| `icmp_packets`, `icmp_bytes` | ICMP statistics |
| `other_packets`, `other_bytes` | Other protocol statistics |
| `tcp_syn`, `tcp_ack`, `tcp_rst`, `tcp_fin` | TCP flag counts |

### Anomaly Detection

**Normal Traffic**: Low reconstruction error (X ≈ A*F)
**Anomalous Traffic**: High reconstruction error (X ≠ A*F)

Threshold: 95th percentile of training errors (configurable)

---

## 💡 Example Use Case: DDoS Detection

### Scenario
Detect Carpet Bombing DDoS where attacker spreads traffic across many IPs.

### Steps

```bash
# 1. Extract features from normal traffic
cd cpp/build
./ipflow_extractor ../../data/normal_traffic.pcap ../../data/stats.json

# 2. Train on normal traffic patterns
cd ../../python
python analyze_features.py ../cpp/build/features.csv --mode train --n_components 5

# 3. Analyze suspicious traffic
cd ../cpp/build
./ipflow_extractor ../../data/suspicious_traffic.pcap ../../data/stats.json

# 4. Detect anomalies
cd ../../python
python analyze_features.py ../cpp/build/features.csv --mode detect

# Output: Identifies IPs with anomalous SYN rates, unusual byte distributions, etc.
```

### Detected Behavior Patterns

**Feature Basis 0**: Normal Web Traffic (high TCP ACK, moderate bytes)
**Feature Basis 1**: DNS Traffic (high UDP, small packets)
**Feature Basis 2**: **SYN Flood Pattern** (high TCP SYN, low bytes) ← Attack indicator
**Feature Basis 3**: Large Data Transfer (high bytes, low packet count)
**Feature Basis 4**: ICMP Echo (high ICMP packets)

Anomalous IPs show high weights on Basis 2 (attack pattern).

---

## 📈 Performance

| Metric | C++ Extractor | Python Analysis |
|--------|---------------|-----------------|
| **Speed** | ~1.3M packets/min | <1s for 1000 samples |
| **Memory** | Stable (auto cleanup) | <100MB for typical models |
| **Scalability** | 100MB+ PCAP files | 10K+ samples |

---

## 🛠️ Building & Installation

### Prerequisites

**C++:**
- C++17 compiler (GCC 7+)
- CMake 3.10+

**Python:**
- Python 3.7+
- Dependencies: `pip install -r python/requirements.txt`

### Build Instructions

```bash
# Build C++ extractor
cd cpp
mkdir build && cd build
cmake ..
make

# Install Python dependencies
cd ../../python
pip install -r requirements.txt
```

---

## 📚 Research Background

This implementation is inspired by research on network traffic decomposition:

- **Lee & Seung (2001)**: Non-negative Matrix Factorization algorithms
- **Lakhina et al. (2005)**: Structural analysis of network traffic flows
- **Xu et al. (2006)**: Bipartite graph analysis for traffic decomposition

**Key Insight**: Network traffic can be represented as linear combinations of latent behavior patterns, enabling detection of distributed attacks like Carpet Bombing.

---

## 🔧 Configuration

### Window Parameters

Edit `data/stats.json`:

```json
{
  "window_size": 2,      // seconds
  "slide_step": 1,       // seconds
  "target_ips": [...],   // IPs to analyze
  "output_file": "features.csv"
}
```

**Recommendations:**
- Real-time detection: 1-5s windows
- Pattern analysis: 10-60s windows
- Long-term trends: 60s+ windows

### Decomposition Parameters

```bash
# Number of behavior patterns (k)
python analyze_features.py data.csv --n_components 5

# Decomposition method
python analyze_features.py data.csv --method nmf  # or 'pca'

# Anomaly threshold
python analyze_features.py data.csv --mode detect --percentile 95
```

---

## 🤝 Contributing

This project is for research and educational purposes. Contributions welcome!

---

## 📄 License

This project is provided for learning and research use.

---

## 📧 Contact

For questions or collaboration: See GitHub repository issues.

---

## 🔄 Changelog

### Version 2.0.0 (2024-10)
- ✨ **New**: Complete Python matrix decomposition module
- ✨ **New**: Anomaly detection functionality
- ✨ **New**: Visualization tools
- 🔄 **Changed**: Features from packet-length histograms to protocol statistics
- 🔄 **Changed**: Default window parameters (60s→2s, 30s→1s)
- 📚 **Added**: Comprehensive documentation

### Version 1.0.0 (2024-10)
- 🎉 **Initial**: C++ PCAP feature extractor
- 📊 **Feature**: Sliding window analysis
- 📝 **Feature**: CSV output format
