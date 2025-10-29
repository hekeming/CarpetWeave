# IPv4 Flow Feature Extractor - Analysis Framework
# Version 1.2 - Research Validation Experiments

## Overview
This module conducts validation experiments to analyze behavioral flow decomposition of network traffic.

**Focus**: Research validation, NOT anomaly detection

## Research Questions

### Question 1: Stability
Does stable decomposition pattern exist in normal traffic?

### Question 2: Low-Rank Property
Can traffic be represented by a small number of basis vectors?

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run stability experiment
python stability_experiment.py ../cpp/build/features.csv --output ./results

# Run low-rank experiment  
python low_rank_experiment.py ../cpp/build/features.csv --output ./results
```

## Modules

- **matrix_analysis.py**: Core analysis classes
- **stability_experiment.py**: Temporal stability analysis
- **low_rank_experiment.py**: Rank analysis
- **utils.py**: Helper functions

## Expected Results

**High Stability (>0.7)**: Consistent traffic patterns exist
**Low Rank (<10)**: Few behavioral patterns dominate

See individual scripts for detailed output.