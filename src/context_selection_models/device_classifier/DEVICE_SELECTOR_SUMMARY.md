# Device Selector Summary

## Overview

The **Device Selector** is a machine learning model that classifies network traffic into device contexts. It's part of Phase 2 (Context Selection) in the MoE pipeline, specifically used for **non-encrypted traffic** to determine which expert model should be used.

## Purpose

When traffic is **not encrypted**, the MoE system needs to choose the right expert model. The Device Selector helps by:
- Identifying the **device type** from network traffic patterns
- Routing to the appropriate expert model (e.g., Doorbell-specific vs Other devices)

## Architecture

The Device Selector consists of **three components** that work together:

### 1. **Meta-Feature Extraction** (pymfe)
- **Tool**: Python Meta-Feature Extraction library (`pymfe`)
- **Purpose**: Extracts statistical and general meta-features from network traffic data
- **Features**: 48 meta-features extracted from raw packet data
  - Groups: `["general", "statistical"]`
  - Summaries: `["mean", "sd"]` (mean and standard deviation)
- **Input**: Raw packet DataFrame (network traffic features)
- **Output**: 48-dimensional feature vector

### 2. **Feature Scaler** (`device_selector_scaler_pymfe.pkl`)
- **Type**: `sklearn.preprocessing.StandardScaler`
- **Purpose**: Normalizes meta-features to zero mean and unit variance
- **Why**: Ensures all features are on the same scale for the classifier
- **Process**: `X_scaled = scaler.transform(X_raw)`

### 3. **Device Classifier** (`device_selector_classifier_pymfe.pkl`)
- **Type**: `sklearn.ensemble.RandomForestClassifier`
- **Configuration**:
  - `n_estimators=100` (100 decision trees)
  - `max_depth=10` (tree depth limit)
  - `class_weight='balanced'` (handles class imbalance)
  - `random_state=42` (reproducibility)
- **Classes**: 
  - `'Doorbell'` - Danmini Doorbell device traffic
  - `'Other'` - Other IoT devices (CICIOT lab devices)
- **Output**: 
  - Predicted class: `'Doorbell'` or `'Other'`
  - Confidence: Probability of prediction

## How It Works

### Training Process (from `Device-Selector.ipynb`)

1. **Data Collection**:
   - **Doorbell Context**: 6 files from `selector-data/Doorbell-data/`
     - `ack`, `benign_traffic`, `scan`, `syn`, `udp`, `udpplain`
   - **Other Context**: 13 files from `selector-data/Other-devices-data/`
     - Benign traffic and various Mirai botnet attacks
     - `Mirai-greeth_flood`, `Mirai-greip_flood`, `Mirai-udpplain`, etc.

2. **Chunking Strategy**:
   - **Chunk Size**: 5000 rows per chunk
   - **Stride**: 10000 rows (50% overlap)
   - **Coverage**: ~50% of each file sampled
   - **Purpose**: Creates multiple training samples from each file

3. **Feature Extraction**:
   - For each chunk:
     - Load chunk DataFrame
     - Extract 48 meta-features using `pymfe.MFE`
     - Handle infinite/NaN values (replace with 0.0)
   - Result: 150 total samples (70 Doorbell, 80 Other)

4. **Model Training**:
   - Normalize features with `StandardScaler`
   - Train/test split: 80/20 (stratified)
   - Train Random Forest classifier
   - Evaluate with cross-validation (5-fold)

5. **Performance**:
   - **Test Accuracy**: ~97% (30/30 correct on test set)
   - **Cross-Validation**: High accuracy with low variance
   - **Confusion Matrix**:
     ```
     Doorbell: 13/14 correct (93% recall)
     Other:    16/16 correct (100% recall)
     ```

### Prediction Process

1. **Input**: Raw packet DataFrame (network traffic features)
2. **Step 1 - Meta-Feature Extraction**:
   ```python
   mfe = MFE(groups=["general", "statistical"], summary=["mean", "sd"])
   mfe.fit(df.values, None)
   feature_names, feature_values = mfe.extract()
   ```
3. **Step 2 - Normalization**:
   ```python
   X_scaled = scaler.transform([feature_values])
   ```
4. **Step 3 - Classification**:
   ```python
   prediction = model.predict(X_scaled)[0]  # 'Doorbell' or 'Other'
   probabilities = model.predict_proba(X_scaled)[0]  # Confidence scores
   ```

## Integration with MoE Pipeline

### Phase 2: Context Selection

```python
def select_ai_model(packet_data, is_encrypted, protocol_type):
    if is_encrypted:
        return 'tls_model'  # Encrypted → TLS expert
    else:
        # Non-encrypted → Use Device Selector
        device_type = device_selector.predict(packet_data)
        
        if device_type == 'Doorbell':
            return 'doorbell_model'  # Route to Doorbell expert
        else:
            return 'other_model'  # Route to Other devices expert
```

### Workflow

```
Non-Encrypted Traffic
    ↓
Extract Meta-Features (pymfe)
    ↓
Normalize Features (scaler)
    ↓
Classify Device Type (Random Forest)
    ↓
Route to Expert Model:
    - 'Doorbell' → Danmini Doorbell expert
    - 'Other' → CICIOT/Multi-device expert
```

## Key Characteristics

### Strengths
- ✅ **Behavior-based**: Uses network flow patterns, not payload content
- ✅ **Robust**: Handles class imbalance with balanced weights
- ✅ **Efficient**: Meta-features reduce dimensionality (48 features from raw data)
- ✅ **Accurate**: ~97% accuracy on test set

### Limitations
- ⚠️ **Binary Classification**: Only distinguishes Doorbell vs Other (2 classes)
- ⚠️ **Chunk-based**: Requires sufficient data (5000+ rows recommended)
- ⚠️ **Meta-feature dependency**: Requires `pymfe` library

### Dependencies
- `pymfe` - Meta-feature extraction
- `sklearn` - Random Forest and StandardScaler
- `pandas`, `numpy` - Data processing

## File Structure

```
src/context_selection_models/
├── Device-Selector.ipynb              # Training notebook
├── device_selector_scaler_pymfe.pkl  # Feature scaler (StandardScaler)
└── device_selector_classifier_pymfe.pkl  # Classifier (RandomForest)
```

## Usage Example

```python
import joblib
import pandas as pd
from pymfe.mfe import MFE
import numpy as np

# Load models
scaler = joblib.load('device_selector_scaler_pymfe.pkl')
classifier = joblib.load('device_selector_classifier_pymfe.pkl')

# Load packet data
packet_data = pd.DataFrame(...)  # Your network traffic DataFrame

# Extract meta-features
mfe = MFE(groups=["general", "statistical"], summary=["mean", "sd"])
mfe.fit(packet_data.values, None)
_, feature_values = mfe.extract()

# Clean values
feature_values = [0.0 if not np.isfinite(v) else v for v in feature_values]

# Normalize and predict
X_scaled = scaler.transform([feature_values])
prediction = classifier.predict(X_scaled)[0]
confidence = classifier.predict_proba(X_scaled)[0].max()

print(f"Device Type: {prediction} (Confidence: {confidence:.2%})")
```

## Next Steps for Integration

1. **Create wrapper function** in `src/moe/integration.py`:
   ```python
   def select_device_context(packet_data: pd.DataFrame) -> str:
       # Load models
       # Extract meta-features
       # Normalize and predict
       # Return 'Doorbell' or 'Other'
   ```

2. **Update `select_ai_model()`** to use device selector for non-encrypted traffic

3. **Handle edge cases**:
   - Insufficient data (< 5000 rows)
   - Missing pymfe library
   - Invalid feature extraction

4. **Add logging** for device selection decisions

## Summary

The Device Selector is a **meta-feature-based Random Forest classifier** that:
- Extracts 48 statistical/general meta-features from network traffic using `pymfe`
- Normalizes features using `StandardScaler`
- Classifies traffic as **'Doorbell'** or **'Other'** device type
- Achieves ~97% accuracy
- Routes non-encrypted traffic to the appropriate expert model in the MoE pipeline

