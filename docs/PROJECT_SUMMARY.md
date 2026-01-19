# PROJECT SUMMARY: Mixture of Experts for C2 Traffic Detection

## OVERALL PROJECT ARCHITECTURE

This is a **Mixture of Experts (MoE)** system for detecting Command and Control (C2) traffic across different network contexts.

### High-Level Flow:

1. **First Decision Point: Encryption Detection**
   - Deterministic tool checks if traffic is **Encrypted** or **Not Encrypted**

2. **If Encrypted (TLS/QUIC/DTLS):**
   - Route to **TLS AI Model**
   - Model decides: **QUIC vs TLS vs DTLS**
   - Also checks: Can encrypted DNS traffic be recognized?
   - **YOUR WORK FITS HERE** - TLS 1.3 C2 detection using behavior-based features

3. **If Not Encrypted:**
   - Use **AI Selector Model** to choose expert
   - Experts include:
     - **Device-based classification** (e.g., CICIOT lab, Danmini Doorbell)
     - **Protocol-based classification** (e.g., MQTT, COAP, RTSP, DNS)
   - **TEAMMATES' WORK FITS HERE** - Various IoT botnet detection contexts

4. **Infrastructure Components:**
   - Table of accuracy per context/AI model
   - Trained AI models
   - Enhancement: Best 2 results for each context
   - Light retraining: DPI (Deep Packet Inspection)

---

## YOUR WORK: TLS 1.3 C2 DETECTION (Encrypted Context)

### Source Paper
**"Extending C2 Traffic Detection Methodologies: From TLS 1.2 to TLS 1.3-enabled Malware"**

GitHub Repository: `extending12to13/` (from published paper's codebase)

### Key Challenge
TLS 1.3 encrypts more handshake information than TLS 1.2, making traditional certificate-based detection less effective. Behavior-based detection using network flow patterns becomes crucial.

### Methodology

#### 1. **Two Detection Approaches Tested:**

**A. Certificate-Based (C-CERT)** - `03-C-CERT.ipynb`
- Uses TLS/SSL certificate metadata (size, issuer, validity)
- Works well for TLS 1.2, less effective for TLS 1.3
- Feature: Certificate length inferred from network behavior

**B. Behavior-Based (C-BEHAV)** - `04-C-BEHAV.ipynb` ⭐ **MAIN FOCUS**
- Uses network flow patterns without inspecting payload
- Features: Packet sizes (`tls_b`), directionality (`tls_dir`), timing (`tls_tp`)
- Works for both TLS 1.2 and TLS 1.3
- **Core feature set:** `joy_indices_tls_half` = first 10 `tls_b` + first 10 `tls_dir` (20 features total)

#### 2. **Datasets Used:**

| Dataset | Type | Purpose | Source |
|---------|------|---------|--------|
| **MTA** | Malware Traffic | Training benign/malicious | https://malware-traffic-analysis.net |
| **Tranco** | Web Traffic (TLS 1.2 & 1.3) | Testing benign | https://osf.io/zq9vs/ |
| **Metasploit (MS)** | C2 Traffic | Training/testing malicious | https://osf.io/b64e5/ |
| **DoH (DNS over HTTPS)** | Encrypted DNS | Testing benign | https://www.unb.ca/cic/datasets/dohbrw-2020.html |

**File Structure:**
- `processed-datasets/`: Preprocessed CSV files
- `data/ms/`: Metasploit raw data (certificates_length.csv, pcap files)
- `data/doh/`: DoH behavior features
- `data/mta/`: MTA labels and metadata

#### 3. **Train/Test Split Strategy:**

- **StratifiedGroupKFold** (5 folds) to prevent data leakage
- Groups by `file` ID to ensure same file doesn't appear in both train/test
- **TLS 1.2 data used for training**, **TLS 1.3 data used for testing** (tests generalization)

**Specific Split:**
- Train: MTA (benign) + Tranco TLS 1.2 (benign) + MS TLS 1.2 (malicious)
- Test sets:
  - TLS 1.2 Baseline: MTA test, Tranco TLS 1.2 test, MS TLS 1.2 (short/long certs)
  - TLS 1.3 Filtered: Tranco TLS 1.3, MS TLS 1.3 (before behavior extraction)
  - TLS 1.3 With Behavior: Tranco TLS 1.3, MS TLS 1.3 (after behavior extraction), DoH

#### 4. **Models Trained:**

| Model | Code | Status | Performance (TLS 1.3 With Behavior) |
|-------|------|--------|-------------------------------------|
| **Decision Tree (DT)** | `04-C-BEHAV.ipynb` | ✅ Trained | ~95-96% TNR, ~95% TPR |
| **Random Forest (RF)** | `04-C-BEHAV.ipynb` | ✅ Trained | ~98% TNR, ~97% TPR |
| **KNN** | `05-Additional-Models-BEHAV.py` | ✅ Trained | ~98% TNR, ~96% TPR |
| **XGBoost (XGB)** | `05-Additional-Models-BEHAV.py` | ✅ Trained | ~99.8% TNR, ~97% TPR ⭐ Best |
| **Extra Trees (ET)** | `05-Additional-Models-BEHAV.py` | ✅ Trained | ~99.8% TNR, ~93% TPR |
| **Deep Neural Network (DNN)** | `05-Additional-Models-BEHAV.py` | ✅ Trained | ~99.9% TNR, ~90% TPR |
| **Logistic Regression (LR)** | `05-Additional-Models-BEHAV.py` | ⚠️ Not used | Too slow, convergence issues |

#### 5. **Training Details:**

**Hyperparameter Tuning:**
- `GridSearchCV` with `StratifiedGroupKFold` (10-fold CV)
- Scoring: AUC, Accuracy, Balanced Accuracy, Recall, F1
- Best model selected based on F1 score (refit='F1')

**Feature Engineering:**
- Behavior extraction from TLS 1.3 flows (packet sizes, directions)
- Error injection for training: `error_mask` and `error_to_add` logic
- Features: `joy_indices_tls_half` = first 10 `tls_b` + first 10 `tls_dir`

**Model Persistence:**
- All models saved to `saved_models/` directory
- Format: `{model_name}_model_{timestamp}.pkl` (or `.h5` for DNN)
- Loading: `pickle.load()` for sklearn models, `keras.models.load_model()` for DNN

#### 6. **Key Results:**

**TLS 1.3 With Behavior Extraction (MAIN RESULT):**

| Model | Tranco TLS 1.3 (TNR) | MS TLS 1.3 Short (TPR) | MS TLS 1.3 Long (TPR) | DoH (TNR) |
|-------|---------------------|----------------------|---------------------|-----------|
| Random Forest | ~98.20% | ~96.07% | ~95.82% | ~95.45% |
| Decision Tree | ~98.20% | ~96.07% | ~95.82% | ~95.45% |
| KNN | ~98.20% | ~96.07% | ~96.07% | ~95.45% |
| XGBoost | ~99.80% | ~97.41% | ~97.25% | ~99.51% ⭐ |
| Extra Trees | ~99.78% | ~93.64% | ~93.15% | ~99.43% |
| DNN | ~99.87% | ~90.08% | ~89.87% | ~99.59% |

**Key Finding:** XGBoost performs best overall, achieving highest TPR while maintaining excellent TNR. DNN has highest TNR but lower TPR for malicious traffic.

#### 7. **Files Created/Modified:**

**Original Notebooks (from paper):**
- `04-C-BEHAV.ipynb` - Main behavior-based detection notebook (Random Forest, Decision Tree)

**Additional Scripts Created:**
- `05-Additional-Models-BEHAV.py` - Trains additional models (KNN, XGBoost, Extra Trees, LR, DNN)
  - Usage: `python 05-Additional-Models-BEHAV.py --models knn xgb et dnn --save-models`
  - Command-line arguments: `--models` (select models), `--save-models` (save trained models)

- `06-Test-Saved-Models.py` - Loads and evaluates saved models without retraining
  - Usage: `python 06-Test-Saved-Models.py --models rf dt knn xgb et dnn`
  - Finds latest saved model for each type and evaluates on test sets

- `07-Save-RF-DT-Models.py` - Helper script to save RF and DT models from notebook methodology

- `08-Package-For-Demo.sh` - Packages demo (models, test datasets, scripts, README)
  - Creates `c2-detection-demo-package/` directory with:
    - All trained models (`saved_models/`)
    - Test datasets (`processed-datasets/`, `data/doh/`)
    - Test script (`06-Test-Saved-Models.py`)
    - README (`README-DEMO.md`)
    - Requirements (`requirements-demo.txt`)

#### 8. **Important Notes:**

- **Behavior-Only Constraint:** All features must be derivable from network flow metadata (packet sizes, timing, direction) without inspecting payload content
- **No Certificate Inspection:** TLS 1.3 encrypts certificate, so features must come from flow behavior
- **Cross-Protocol Generalization:** Model trained on TLS 1.2, tested on TLS 1.3 (proves generalization)
- **Data Leakage Prevention:** `StratifiedGroupKFold` ensures same file never in both train/test
- **Reproducibility:** Fixed random seeds (42) throughout

---

## TEAMMATES' WORK: IoT BOTNET DETECTION (Not Encrypted Contexts)

### Context 1: Multiple IoT Protocols (MQTT, COAP, RTSP)
- **Paper:** https://arxiv.org/pdf/2502.03134
- **Context:** Not encrypted IoT traffic (MQTT, COAP, RTSP protocols)
- **Focus:** Command and Control detection across multiple protocols
- **Note:** Check if uses behavior-only features or includes payload inspection

### Context 2: Danmini Doorbell Device (Single Device)
- **Code:** https://github.com/dineshh912/IoT-botnet-attack-detection
- **Dataset:** https://archive.ics.uci.edu/dataset/442/detection+of+iot+botnet+attacks+n+baiot
- **Context:** Single IoT device (Danmini Doorbell) under Mirai botnet attacks
- **Focus:** Device-specific C2 detection
- **Subset Used:** Only Danmini Doorbell portion of full BA-IoT dataset

### Context 3: CICIOT Lab (Multiple IoT Devices)
- **Dataset/Paper:** https://github.com/yliang725/Anomaly-Detection-IoT23/blob/main/Research%20Paper/Research%20Paper.pdf
- **Context:** Mirai attacks on multiple IoT devices in CICIOT lab
- **Focus:** Multi-device IoT botnet detection

### Context 4: DNS-Based C&C (IoT23 Dataset)
- **Context:** DNS-based Command & Control traffic from IoT23 dataset
- **Data Preprocessing:** Custom script `process_iot23_cc_dns_features.py`
- **Processing:**
  - Filtered 30.9M+ network flows for C&C attacks and benign traffic
  - Extracted DNS-related behavioral features:
    - Port-based indicators (DNS port 53)
    - Service-type classification
    - DNS-like traffic patterns (packet size, protocol characteristics)
- **Class Balancing:** 1:10 ratio (9.09% C&C attacks, 90.91% benign)
- **Final Dataset:** 622,094 samples (9.09% C&C attacks, 90.91% benign)
- **Note:** Check if uses behavior-only features or includes DNS domain names (which would violate "behavior-only" constraint)

### Important Constraint for All Contexts:
**Behavior-Only Features Required:**
- Should use: Packet sizes, timing, direction, port numbers, protocol characteristics
- **Potentially Problematic:** DNS domain names, MQTT topics, COAP/RTSP payload content (these come from application-layer payload, not pure network behavior)
- **Acceptable if Behavior-Based:** Port numbers (53 for DNS, 1883 for MQTT), packet size patterns, timing patterns, protocol headers (not payload)

---

## FILE STRUCTURE SUMMARY

```
extending12to13/
├── 04-C-BEHAV.ipynb                    # Original notebook (RF, DT)
├── 05-Additional-Models-BEHAV.py       # Additional models training
├── 06-Test-Saved-Models.py             # Test saved models
├── 07-Save-RF-DT-Models.py             # Helper for RF/DT saving
├── 08-Package-For-Demo.sh              # Demo packaging script
├── saved_models/                       # All trained models
│   ├── random_forest_model_*.pkl
│   ├── decision_tree_model_*.pkl
│   ├── knn_model_*.pkl
│   ├── xgb_model_*.pkl
│   ├── extratrees_model_*.pkl
│   └── dnn_model_*.h5
├── processed-datasets/                 # Preprocessed data
│   ├── ms-tls12-data.csv
│   ├── ms-tls13-behav.csv
│   ├── tranco-tls12-data.csv
│   ├── tranco-tls13-behav-new.csv
│   └── mta_tlsdata.csv
├── data/
│   ├── ms/
│   │   └── certificates_length.csv
│   ├── doh/
│   │   └── tls13-behav.csv
│   └── mta/
└── c2-detection-demo-package/          # Demo package (ready for deployment)
    ├── saved_models/
    ├── processed-datasets/
    ├── data/doh/
    ├── 06-Test-Saved-Models.py
    ├── README-DEMO.md
    └── requirements-demo.txt
```

---

## KEY TECHNICAL DETAILS

### Feature Sets:
- `tls_b_0` to `tls_b_19`: Packet size features (first 20 packets)
- `tls_dir_0` to `tls_dir_19`: Direction features (first 20 packets)
- `tls_tp_0` to `tls_tp_19`: Timing features (first 20 packets)
- `joy_indices_tls_half`: First 10 `tls_b` + first 10 `tls_dir` (20 features) ⭐ **USED IN BEHAV**

### Evaluation Metrics:
- **TNR (True Negative Rate):** % of benign correctly identified as benign
- **TPR (True Positive Rate/Recall):** % of malicious correctly identified as malicious
- **AUC:** Area Under ROC Curve
- **F1 Score:** Harmonic mean of precision and recall

### Train/Test Split Logic:
```python
# StratifiedGroupKFold to prevent leakage
sgkf = StratifiedGroupKFold(n_splits=5)
train_index, test_index = next(sgkf.split(x, y, groups))

# Metasploit split: half files for test, avoiding longcert overlap
metasploit_test_files = np.random.choice(...)
```

### Model Training Pattern:
```python
# GridSearchCV with StratifiedGroupKFold
sgkf = StratifiedGroupKFold(n_splits=10)
grid_search = GridSearchCV(
    estimator,
    param_grid,
    cv=sgkf,
    scoring={'AUC': 'roc_auc', 'F1': 'f1', ...},
    refit='F1',
    n_jobs=-1
)
```

---

## DEPENDENCIES & ENVIRONMENT

- **Python Version:** 3.9 (original paper used 3.10, but environment is 3.9)
- **Key Packages:**
  - `pandas`, `numpy`
  - `scikit-learn` (Random Forest, Decision Tree, KNN, Extra Trees, Logistic Regression)
  - `xgboost` (requires `libomp` on macOS: `brew install libomp`)
  - `tensorflow`/`keras` (for DNN)
- **Virtual Environment:** `tls13-env/` (already configured)
- **Requirements:** `requirements.txt` in main directory

---

## REPRODUCTION STEPS

1. **Activate environment:**
   ```bash
   source tls13-env/bin/activate
   ```

2. **Run original notebook:**
   ```bash
   jupyter notebook 04-C-BEHAV.ipynb
   ```

3. **Train additional models:**
   ```bash
   python 05-Additional-Models-BEHAV.py --models knn xgb et dnn --save-models
   ```

4. **Test saved models:**
   ```bash
   python 06-Test-Saved-Models.py --models all
   ```

5. **Package for demo:**
   ```bash
   bash 08-Package-For-Demo.sh
   ```

---

## NEXT STEPS FOR INTEGRATION

1. **Create Deterministic Encryption Detection Tool**
   - Check if traffic is encrypted (TLS/QUIC) or not encrypted
   - Route to appropriate expert

2. **Integrate TLS Models into MoE System**
   - Load saved models (`saved_models/`)
   - Implement routing: QUIC vs TLS vs DTLS decision
   - Test encrypted DNS detection capability

3. **Integrate Teammates' Models**
   - Load IoT botnet models (MQTT, COAP, RTSP, DNS, device-based)
   - Implement selector model for not-encrypted contexts
   - Verify behavior-only constraint compliance

4. **Create Accuracy Table**
   - Compile results from all contexts
   - Best 2 models per context
   - Document performance metrics

5. **Light Retraining with DPI**
   - Enhance models with Deep Packet Inspection features (if applicable)
   - Evaluate performance improvement

---

## QUESTIONS TO CLARIFY

1. **Behavior-Only Constraint:**
   - Do teammates' contexts strictly use behavior-only features?
   - Are DNS domain names, MQTT topics considered acceptable? (They come from payload, not pure network behavior)

2. **Model Selection:**
   - Which models from each context should be integrated? (Best 2?)
   - How to handle different feature sets across contexts?

3. **Selector Model:**
   - How to determine which expert to use for not-encrypted traffic?
   - Protocol detection? Device fingerprinting? Context clues?

4. **Encryption Detection:**
   - What deterministic tool to use for encryption detection?
   - Port-based? Protocol handshake? Packet characteristics?

---

## CONTACT & REFERENCES

- **Original Paper Repository:** Check `extending12to13/README.md` for citations
- **Datasets:** See `extending12to13/README.md` for download links
- **Model Files:** All saved in `saved_models/` directory
- **Demo Package:** Ready in `c2-detection-demo-package/` or `.zip` file

---

**END OF PROJECT SUMMARY**

