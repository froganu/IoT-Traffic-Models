# TLS 1.3 C2 Detection - Directory Structure

This document describes the expected directory structure for the `extending12to13/` folder containing the TLS 1.3 C2 detection implementation.

## Directory Structure

```
extending12to13/
├── 04-C-BEHAV.ipynb                    # Original notebook (RF, DT)
├── 05-Additional-Models-BEHAV.py       # Additional models training
├── 06-Test-Saved-Models.py             # Test saved models
├── 07-Save-RF-DT-Models.py             # Helper for RF/DT saving
├── 08-Package-For-Demo.sh              # Demo packaging script
├── README.md                            # Original paper README
├── requirements.txt                     # Python dependencies
├── saved_models/                        # All trained models
│   ├── random_forest_model_*.pkl
│   ├── decision_tree_model_*.pkl
│   ├── knn_model_*.pkl
│   ├── xgb_model_*.pkl
│   ├── extratrees_model_*.pkl
│   └── dnn_model_*.h5
├── processed-datasets/                  # Preprocessed data
│   ├── ms-tls12-data.csv
│   ├── ms-tls13-behav.csv
│   ├── tranco-tls12-data.csv
│   ├── tranco-tls13-behav-new.csv
│   └── mta_tlsdata.csv
├── data/
│   ├── ms/
│   │   ├── certificates_length.csv
│   │   └── [pcap files]
│   ├── doh/
│   │   └── tls13-behav.csv
│   └── mta/
│       └── [MTA labels and metadata]
└── c2-detection-demo-package/           # Demo package (ready for deployment)
    ├── saved_models/
    ├── processed-datasets/
    ├── data/doh/
    ├── 06-Test-Saved-Models.py
    ├── README-DEMO.md
    └── requirements-demo.txt
```

## Key Files Description

### Notebooks and Scripts

- **04-C-BEHAV.ipynb**: Main behavior-based detection notebook
  - Implements Random Forest and Decision Tree models
  - Uses `joy_indices_tls_half` features (20 features: first 10 `tls_b` + first 10 `tls_dir`)
  - Implements StratifiedGroupKFold for train/test split
  - Evaluates on TLS 1.2 and TLS 1.3 datasets

- **05-Additional-Models-BEHAV.py**: Trains additional models
  - Models: KNN, XGBoost, Extra Trees, Logistic Regression, DNN
  - Command-line interface for model selection
  - Saves trained models to `saved_models/`

- **06-Test-Saved-Models.py**: Evaluates saved models
  - Loads models without retraining
  - Tests on all test datasets
  - Generates performance reports

- **07-Save-RF-DT-Models.py**: Helper script
  - Saves Random Forest and Decision Tree models from notebook
  - Ensures consistency with other saved models

- **08-Package-For-Demo.sh**: Demo packaging script
  - Creates standalone demo package
  - Includes models, test datasets, and scripts
  - Ready for deployment/demonstration

### Data Directories

- **saved_models/**: All trained model files
  - Format: `{model_name}_model_{timestamp}.pkl` (or `.h5` for DNN)
  - Models: RF, DT, KNN, XGB, ET, DNN

- **processed-datasets/**: Preprocessed CSV files
  - Ready for model training/evaluation
  - Includes train/test splits

- **data/ms/**: Metasploit raw data
  - Certificate length data
  - PCAP files for behavior extraction

- **data/doh/**: DNS-over-HTTPS data
  - Behavior features extracted from DoH traffic
  - Used for testing encrypted DNS detection

- **data/mta/**: MTA (Malware Traffic Analysis) data
  - Labels and metadata
  - Used for training benign/malicious classification

## Feature Set

### Core Features (joy_indices_tls_half)
- `tls_b_0` to `tls_b_9`: First 10 packet size features
- `tls_dir_0` to `tls_dir_9`: First 10 direction features
- **Total: 20 features**

### Additional Available Features
- `tls_b_10` to `tls_b_19`: Additional packet size features
- `tls_dir_10` to `tls_dir_19`: Additional direction features
- `tls_tp_0` to `tls_tp_19`: Timing features (not used in main model)

## Model Performance

### Best Models (TLS 1.3 With Behavior)

| Model | TNR (Tranco TLS 1.3) | TPR (MS TLS 1.3) | DoH TNR |
|-------|---------------------|------------------|---------|
| **XGBoost** | 99.80% | 97.41% | 99.51% ⭐ |
| **Random Forest** | 98.20% | 96.07% | 95.45% |
| **KNN** | 98.20% | 96.07% | 95.45% |
| **Decision Tree** | 98.20% | 95.82% | 95.45% |
| **Extra Trees** | 99.78% | 93.64% | 99.43% |
| **DNN** | 99.87% | 90.08% | 99.59% |

**Best 2 Models for Integration:**
1. XGBoost (best overall TPR and TNR)
2. Random Forest (good balance, second best TPR)

## Usage

### Training Models

```bash
# Activate environment
source tls13-env/bin/activate

# Run original notebook
jupyter notebook 04-C-BEHAV.ipynb

# Train additional models
python 05-Additional-Models-BEHAV.py --models knn xgb et dnn --save-models
```

### Testing Models

```bash
# Test all saved models
python 06-Test-Saved-Models.py --models all

# Test specific models
python 06-Test-Saved-Models.py --models xgb rf
```

### Packaging Demo

```bash
bash 08-Package-For-Demo.sh
```

## Integration with MoE System

The TLS models are integrated into the MoE system via:
- `moe_integration.py`: Main MoE integration code
- `trained_models/TLS/`: Models copied/symlinked from `extending12to13/saved_models/`
- TLS Expert class loads models and performs C2 detection

## Dependencies

See `requirements.txt` for full list. Key packages:
- pandas, numpy
- scikit-learn
- xgboost (requires `libomp` on macOS: `brew install libomp`)
- tensorflow/keras (for DNN)

## Notes

- All models use behavior-only features (no payload inspection)
- Models trained on TLS 1.2, tested on TLS 1.3 (proves generalization)
- StratifiedGroupKFold prevents data leakage
- Fixed random seed (42) for reproducibility

