# CarpetWeave

**Address-to-Behavior Traffic Decomposition for Carpet Bombing DDoS Detection**
https://github.com/hekeming/CarpetWeave/blob/main/README.md
CarpetWeave aims to reveal the hidden behavioral structure of network traffic by decomposing observed IP-level flows into latent **behavior flows**.  
This enables accurate detection of **Carpet Bombing DDoS attacks**, where attackers distribute traffic across many IPs to evade traditional per-IP detection.

---

## ✨ Project Goals

- **PCAP → Feature Matrix Pipeline (C++)**  
  Sliding-window or rolling-window feature extraction from raw PCAP, producing time-aligned **IP × Feature** summary matrices.
- **Behavior Decomposition (Python)**  
  Explore NMF / sparse coding / tensor decomposition to recover latent behavior flows.
- **Attack Detection Application**  
  Identify abnormal behavior allocation patterns (e.g., Carpet Bombing DDoS).

---

## 📂 Repository Structure

CarpetWeave/

├─ data/ # Data, sample PCAPs, schemas (no large data committed)

├─ cpp/ # C++ core: PCAP → Feature Matrix (skeleton)

├─ py/ # Python: analysis, visualization, decomposition

└─ docs/ # Architecture & design documentation


### Folder Overview

| Folder | Description |
|--------|--------------|
| `data/` | Holds sample data, schemas, and instructions. Raw PCAPs are NOT committed. |
| `cpp/` | C++ implementation for feature extraction – currently a **skeleton** (no code yet). |
| `py/` | Python notebooks & scripts for visualization and behavior-based detection (to be added). |
| `docs/` | Design notes, architecture diagrams, methodology. |
