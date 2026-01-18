# Architecture, Assumptions, and Expected Flow

## Project Overview

This is a **Mixture of Experts (MoE)** system for detecting Command and Control (C2) traffic at the **PACKET LEVEL**. The system processes individual packets (or packet sequences) and routes them to specialized AI models based on whether the traffic is encrypted or not.

---

## Core Project Idea

### High-Level Concept

```
Network Traffic Flow
    │
    ├─→ [Encryption Detection] ──→ Is Encrypted?
    │                                    │
    │                                    ├─→ YES → [TLS Expert Models]
    │                                    │         - TLS 1.3 C2 Detection
    │                                    │         - Behavior-based features
    │                                    │
    │                                    └─→ NO → [Selector Model] ──→ Choose Expert
    │                                                                    │
    │                                                                    ├─→ DNS Expert
    │                                                                    ├─→ MQTT/COAP/RTSP Expert
    │                                                                    ├─→ Danmini Doorbell Expert
    │                                                                    └─→ CICIOT Lab Expert
```

### Key Principle: **Behavior-Only Detection**
- **Allowed**: Packet sizes, timing, direction, port numbers, protocol characteristics
- **Not Allowed**: Payload content, DNS domain names, MQTT topics (application-layer data)

---

## Current Skeleton Architecture

### File: `moe_integration.py`

#### Assumptions Made:

1. **Input Format (PACKET-LEVEL)**
   - Traffic data comes as a `pandas.DataFrame` (`packet_data`)
   - DataFrame contains **packet-level features** (one row per packet)
   - Each packet has: size, direction, port, protocol, timing, etc.
   - Optional: `packet_bytes` (raw packet bytes) for header inspection
   - Optional: `packet_sequence` (list of previous packets) for sequence-based models

2. **Encryption Detection** (`check_encryption()`)
   - **Assumes**: Can determine encryption status from:
     - Port number (e.g., 443 = encrypted, 53 = not encrypted)
     - Protocol string (e.g., 'tls', 'tcp', 'udp')
     - **Packet header bytes** (e.g., TLS handshake patterns: 0x16 0x03)
     - Packet-level features (if needed)
   - **Returns**: `(is_encrypted: bool, protocol_type: Optional[str])`
   - **Protocol types**: 'tls', 'quic', 'dtls', or None

3. **Model Selection** (`select_ai_model()`)
   - **Assumes**: Model selection is deterministic based on:
     - Encryption status
     - Protocol type (if encrypted)
     - **Packet header fields** (port, protocol, service, etc.)
   - **Returns**: Model identifier string (e.g., 'tls_model', 'dns_model', 'mqtt_model')
   - **Model naming convention**: `{context}_model` (e.g., 'tls_model', 'dns_model')

4. **Model Loading** (`load_model()`)
   - **Assumes**: Models are stored in `trained_models/` directory structure:
     ```
     trained_models/
     ├── TLS/
     ├── DNS/
     ├── MQTT_COAP_RTSP/
     ├── Danmini_Doorbell_Device/
     └── Multiple_IoT_device_types/
     ```
   - **Assumes**: Models can be loaded with standard Python libraries:
     - `pickle` for sklearn models (.pkl files)
     - `keras.models.load_model()` for DNN models (.h5 files)
   - **Returns**: Loaded model object (any type)

4. **Feature Extraction** (`extract_packet_features()`)
   - **Assumes**: Features are extracted from packet(s):
     - For TLS: Need first N packets to extract `tls_b_0-9`, `tls_dir_0-9` (20 features)
     - For DNS: Extract packet size, port, protocol from single packet
     - For sequence-based models: Use `packet_sequence` parameter
   - **Returns**: Feature array (numpy array) ready for model input

5. **Prediction** (`predict_c2()`)
   - **Assumes**: Models follow standard sklearn/keras interface:
     - `model.predict()` for predictions
     - `model.predict_proba()` for probabilities (if available)
   - **Assumes**: Input is feature array (from `extract_packet_features()`)
   - **Returns**: Dictionary with:
     - `is_c2`: bool or array (True = C2 traffic, False = benign)
     - `probability`: float or array (confidence score)
     - `predictions`: array (raw predictions)

6. **Main Function** (`detect_c2()`)
   - **Assumes**: Sequential flow: encryption check → model selection → load → extract features → predict
   - **Assumes**: Works on individual packets or packet sequences
   - **Assumes**: All functions work together seamlessly
   - **Returns**: Combined result dictionary with all information

---

### File: `accuracy_table.py`

#### Assumptions Made:

1. **Storage Format**
   - Accuracy metrics stored in CSV file (`accuracy_table.csv`)
   - Columns: context, model, accuracy, tnr, tpr, precision, f1, auc, dataset, notes

2. **Metrics Tracked**
   - **TNR** (True Negative Rate): % of benign correctly identified
   - **TPR** (True Positive Rate/Recall): % of malicious correctly identified
   - **Accuracy**: Overall accuracy
   - **Precision**: Precision score
   - **F1**: F1 score
   - **AUC**: Area Under ROC Curve

3. **Context Organization**
   - Each context (TLS, DNS, MQTT_COAP_RTSP, etc.) has multiple models
   - Best N models per context can be retrieved
   - Ranking by any metric (default: F1 score)

---

## Expected Flow

### Step-by-Step Execution Flow

```
1. INPUT: packet_data (DataFrame, one row per packet), port, protocol, packet_bytes (optional)
   │
   ├─→ detect_c2(packet_data, port, protocol, packet_bytes, packet_sequence)
   │
2. ENCRYPTION CHECK (from packet header/bytes)
   │
   ├─→ check_encryption(packet_data, port, protocol, packet_bytes)
   │   │
   │   ├─→ Returns: (is_encrypted: bool, protocol_type: str or None)
   │   │
   │   └─→ Logic (TO BE IMPLEMENTED):
   │       - Check port (443 = encrypted, 53 = not encrypted, etc.)
   │       - Check protocol string
   │       - Check packet_bytes for TLS handshake (0x16 0x03), QUIC headers, etc.
   │
3. MODEL SELECTION
   │
   ├─→ select_ai_model(packet_data, is_encrypted, protocol_type)
   │   │
   │   ├─→ Returns: model_name (str)
   │   │
   │   └─→ Logic (TO BE IMPLEMENTED):
   │       IF encrypted:
   │           - If protocol_type == 'tls': return 'tls_model'
   │           - If protocol_type == 'quic': return 'quic_model'
   │           - If protocol_type == 'dtls': return 'dtls_model'
   │       ELSE:
   │           - Check port/protocol from packet header
   │           - Port 53 → 'dns_model'
   │           - Port 1883/8883 → 'mqtt_model'
   │           - Port 5683/5684 → 'coap_model'
   │           - Port 554 → 'rtsp_model'
   │           - Device-based → 'danmini_model' or 'ciciot_model'
   │           - Or use selector model to choose
   │
4. MODEL LOADING
   │
   ├─→ load_model(model_name)
   │   │
   │   ├─→ Returns: model object
   │   │
   │   └─→ Logic (TO BE IMPLEMENTED):
   │       - Map model_name to file path
   │       - Load using pickle (sklearn) or keras (DNN)
   │       - Return loaded model
   │
5. FEATURE EXTRACTION (from packet(s))
   │
   ├─→ extract_packet_features(packet_data, model_name, packet_sequence)
   │   │
   │   ├─→ Returns: feature_array (numpy array)
   │   │
   │   └─→ Logic (TO BE IMPLEMENTED):
   │       - For TLS: Extract first N packets → tls_b_0-9, tls_dir_0-9 (20 features)
   │       - For DNS: Extract packet size, port, protocol from single packet
   │       - For sequence-based: Use packet_sequence if provided
   │       - Return feature array ready for model
   │
6. PREDICTION
   │
   ├─→ predict_c2(model, packet_features)
   │   │
   │   ├─→ Returns: {is_c2, probability, predictions}
   │   │
   │   └─→ Logic (TO BE IMPLEMENTED):
   │       - Call model.predict(packet_features)
   │       - Call model.predict_proba() if available
   │       - Format results
   │
7. OUTPUT: Combined result dictionary
   │
   └─→ {
        'is_encrypted': bool,
        'protocol_type': str or None,
        'model_used': str,
        'is_c2': bool or array,
        'probability': float or array,
        'predictions': array
       }
```

---

## Detailed Assumptions by Component

### 1. Encryption Detection Assumptions

**What we assume:**
- Port numbers are reliable indicators (443 = TLS, 53 = DNS, etc.)
- Protocol strings may be available in metadata
- Flow data may contain encryption-related features

**What needs to be implemented:**
- Port-based detection rules
- Protocol string parsing
- Packet-based detection (TLS handshake patterns, QUIC headers)
- Edge cases (non-standard ports, protocol obfuscation)

**Example Implementation Logic:**
```python
if port == 443:
    return True, 'tls'
elif port == 53:
    return False, None
elif port in [1883, 8883]:  # MQTT
    return False, None
# ... more rules
```

### 2. Model Selection Assumptions

**What we assume:**
- Selection is deterministic (no randomness)
- Can be based on port, protocol, service, or device type
- For encrypted: protocol_type determines model
- For non-encrypted: port/protocol/service determines model OR selector model chooses

**What needs to be implemented:**
- Port-to-model mapping
- Protocol-to-model mapping
- Service-to-model mapping
- Selector model integration (if using AI selector)

**Example Implementation Logic:**
```python
if is_encrypted:
    if protocol_type == 'tls':
        return 'tls_model'
    elif protocol_type == 'quic':
        return 'quic_model'
else:
    if 'id.resp_p' in flow_data.columns:
        if 53 in flow_data['id.resp_p'].values:
            return 'dns_model'
        elif 1883 in flow_data['id.resp_p'].values:
            return 'mqtt_model'
    # ... more rules
```

### 3. Model Loading Assumptions

**What we assume:**
- Models are saved in standard formats:
  - `.pkl` for sklearn models (pickle)
  - `.h5` for Keras/TensorFlow models
- Models are organized by context in `trained_models/` directory
- Model naming convention: `{model_type}_model.pkl` or `{model_type}_model.h5`

**What needs to be implemented:**
- Model name to file path mapping
- Loading logic for each model type
- Error handling (model not found, incompatible format)

**Example Implementation Logic:**
```python
model_paths = {
    'tls_model': 'trained_models/TLS/xgb_model.pkl',
    'dns_model': 'trained_models/DNS/random_forest_model.pkl',
    # ... more mappings
}

if model_name.endswith('.h5'):
    return keras.models.load_model(model_path)
else:
    with open(model_path, 'rb') as f:
        return pickle.load(f)
```

### 4. Prediction Assumptions

**What we assume:**
- Models follow sklearn/keras interface:
  - `model.predict(X)` returns predictions
  - `model.predict_proba(X)` returns probabilities (if available)
- Input features match model's expected features
- Models output binary classification (0 = benign, 1 = C2)

**What needs to be implemented:**
- Feature extraction from flow_data
- Feature alignment with model's expected features
- Handling different model types (sklearn, keras, xgboost)
- Formatting predictions and probabilities

**Example Implementation Logic:**
```python
# Extract features
features = flow_data[required_feature_columns].values

# Predict
predictions = model.predict(features)

# Get probabilities if available
if hasattr(model, 'predict_proba'):
    probabilities = model.predict_proba(features)[:, 1]
else:
    probabilities = None

return {
    'is_c2': predictions == 1,
    'probability': probabilities,
    'predictions': predictions
}
```

---

## Project Contexts and Models

### Encrypted Contexts

| Context | Models Available | Best Models | Features |
|---------|-----------------|-------------|----------|
| **TLS** | XGBoost, RF, DT, KNN, ET, DNN | XGBoost, RF | 20 features: tls_b_0-9, tls_dir_0-9 |
| **QUIC** | (To be implemented) | - | - |
| **DTLS** | (To be implemented) | - | - |

### Non-Encrypted Contexts

| Context | Models Available | Best Models | Features |
|---------|-----------------|-------------|----------|
| **DNS** | (Jaume's models) | - | DNS port, service, patterns |
| **MQTT/COAP/RTSP** | (Pol's models) | - | Protocol-specific features |
| **Danmini Doorbell** | (Ivan/Andrea's models) | - | Device-specific features |
| **CICIOT Lab** | (Team models) | - | Multi-device features |

---

## Data Flow Assumptions

### Input Data Format (PACKET-LEVEL)

**Assumed structure:**
```python
# Single packet or packet sequence
packet_data = pd.DataFrame({
    # Packet-level features (one row per packet)
    'packet_size': [...],      # Size of this packet
    'direction': [...],        # Direction (0=client→server, 1=server→client)
    'dst_port': [...],        # Destination port
    'src_port': [...],        # Source port
    'protocol': [...],        # Protocol (tcp, udp, etc.)
    'timestamp': [...],        # Packet timestamp
    'service': [...],         # Service type (if known)
    
    # For TLS: features extracted from packet sequence
    # (These would be extracted in extract_packet_features())
    # 'tls_b_0': [...], 'tls_b_1': [...], ..., 'tls_b_9': [...],
    # 'tls_dir_0': [...], 'tls_dir_1': [...], ..., 'tls_dir_9': [...],
})

# Optional: Raw packet bytes for header inspection
packet_bytes = b'\x16\x03\x01...'  # Raw packet bytes

# Optional: Sequence of previous packets (for sequence-based models)
packet_sequence = [packet1, packet2, ..., packetN]  # List of DataFrames
```

### Output Format

**Assumed structure:**
```python
result = {
    'is_encrypted': True/False,
    'protocol_type': 'tls' or None,
    'model_used': 'tls_model',
    'is_c2': [True, False, True, ...],  # Array for batch, bool for single
    'probability': [0.95, 0.02, 0.87, ...],  # Array for batch, float for single
    'predictions': [1, 0, 1, ...]  # Array of 0/1
}
```

---

## Integration Points

### Where Teammates' Work Fits

1. **DNS Expert** (Jaume)
   - Model files: `trained_models/DNS/*.pkl`
   - Model name: `'dns_model'`
   - Features: DNS port, service, behavioral patterns

2. **MQTT/COAP/RTSP Expert** (Pol)
   - Model files: `trained_models/MQTT_COAP_RTSP/*.pkl`
   - Model name: `'mqtt_coap_rtsp_model'`
   - Features: Protocol-specific behavioral features

3. **Danmini Doorbell Expert** (Ivan/Andrea)
   - Model files: `trained_models/Danmini_Doorbell_Device/*.pkl`
   - Model name: `'danmini_doorbell_model'`
   - Features: Device-specific features

4. **CICIOT Lab Expert** (Team)
   - Model files: `trained_models/Multiple_IoT_device_types/*.pkl`
   - Model name: `'ciciot_model'`
   - Features: Multi-device features

---

## What's Missing (To Be Implemented)

### Critical TODOs:

1. **`check_encryption()`**
   - [ ] Port-based rules
   - [ ] Protocol string parsing
   - [ ] Packet-based detection (optional)

2. **`select_ai_model()`**
   - [ ] Encrypted model selection (TLS/QUIC/DTLS)
   - [ ] Non-encrypted model selection (port/protocol-based)
   - [ ] Selector model integration (if using AI selector)

3. **`load_model()`**
   - [ ] Model name to file path mapping
   - [ ] Pickle loading for sklearn models
   - [ ] Keras loading for DNN models
   - [ ] Error handling

4. **`predict_c2()`**
   - [ ] Feature extraction per model type
   - [ ] Model prediction interface
   - [ ] Result formatting

5. **Integration**
   - [ ] Load teammates' models
   - [ ] Test end-to-end flow
   - [ ] Handle edge cases

---

## Key Distinction: Packet-Level vs Flow-Level

### Packet-Level Processing
- **Input**: Individual packets (one row per packet in DataFrame)
- **Processing**: Each packet is analyzed separately
- **Features**: Extracted from packet headers and payload metadata (not payload content)
- **Sequence Models**: Some models (e.g., TLS) need first N packets to extract sequence features
  - TLS: First 10 packets → `tls_b_0-9` (sizes) + `tls_dir_0-9` (directions) = 20 features
  - These features are extracted from a packet sequence, not a single packet

### Why Packet-Level?
- More granular detection
- Can detect C2 patterns in early packets (before full flow completes)
- Behavior-based features come from packet characteristics, not aggregated flow stats
- Aligns with TLS 1.3 work: features extracted from first N packets of a connection

## Summary

**Current State:**
- ✅ Skeleton framework with clear structure (PACKET-LEVEL)
- ✅ Defined interfaces and data flow
- ✅ Assumptions documented
- ✅ Packet-level processing architecture
- ❌ Implementation logic (TODOs)

**Next Steps:**
1. Implement encryption detection logic
2. Implement model selection logic
3. Implement model loading
4. Implement prediction logic
5. Integrate teammates' models
6. Test and validate

**Key Principle:**
- Behavior-only features (no payload inspection)
- Deterministic routing (encryption check → model selection)
- Modular design (easy to add new experts)

