# Device Classification Tests - Explanation

## What Device Types Are Possible?

The Device Selector model is a **binary classifier** with **2 possible outputs**:

1. **`'Doorbell'`** - Danmini Doorbell device traffic
   - Represents traffic from the Danmini Doorbell IoT device
   - Trained on Doorbell-specific network patterns
   - Routes to: `doorbell_model` expert

2. **`'Other'`** - Other IoT devices (CICIOT lab devices)
   - Represents traffic from other IoT devices (not Doorbell)
   - Includes various devices from CICIOT lab dataset
   - Routes to: Protocol-based experts (DNS, MQTT, etc.) or multi-device models

### Model Output Format

```python
device_type, confidence = select_device_context(packet_data)
# device_type: 'Doorbell' or 'Other'
# confidence: float (0.0-1.0) - probability of prediction
```

## What Do the Tests Test For?

### 1. `test_device_selector_basic.py`

**Purpose**: Test basic device selector functionality

**What it tests:**
- ✅ **Model Loading**: Can the trained models be loaded successfully?
  - Verifies `scaler` and `classifier` files exist and load correctly
  - Checks model types (StandardScaler, RandomForestClassifier)
  - Verifies classes: `['Doorbell', 'Other']`

- ✅ **Classification with Sufficient Data**: Can it classify device type?
  - Tests with 100 packets (sufficient for meta-feature extraction)
  - Verifies it returns a valid device type (`'Doorbell'` or `'Other'`)
  - Checks confidence score is reasonable (0.0-1.0)

- ✅ **Small Dataset Handling**: How does it handle insufficient data?
  - Tests with 5 packets (may be too small)
  - Verifies graceful handling (may return `None` for very small datasets)

**Expected Results:**
- Models load successfully
- Classification works with sufficient data (100+ packets)
- Small datasets handled gracefully (may return `None`)

---

### 2. `test_device_selector_integration.py`

**Purpose**: Test device selector integration with full MoE pipeline

**What it tests:**
- ✅ **Phase 1 → Phase 2 Flow**: Full pipeline execution
  - Phase 1: Encryption detection (should detect as non-encrypted)
  - Phase 2: Context selection (should use device selector)

- ✅ **Device Selector Usage**: Is device selector called for non-encrypted traffic?
  - Verifies device selector is attempted
  - Checks if device selector is available or falls back to port-based routing

- ✅ **Model Selection**: Does it route to correct expert model?
  - If device selector succeeds: routes to `doorbell_model` or continues to port-based
  - If device selector unavailable: falls back to port-based routing (e.g., `mqtt_model`)

**Expected Results:**
- Non-encrypted traffic triggers device selector
- Device selector integrates with `select_ai_model()` function
- Fallback to port-based routing works when device selector unavailable

---

### 3. `test_device_selector_error_handling.py`

**Purpose**: Test error handling and edge cases

**What it tests:**
- ✅ **Empty DataFrame**: Can it handle empty input?
  - Tests with `pd.DataFrame()` (0 rows, 0 columns)
  - Expected: Returns `(None, None)` gracefully

- ✅ **Very Small Datasets**: Can it handle minimal data?
  - Tests with 5 rows (may be insufficient for meta-features)
  - Tests with 1 row (definitely insufficient)
  - Expected: Returns `(None, None)` or handles gracefully

- ✅ **Minimal Features**: Can it work with limited columns?
  - Tests with only `packet_size` column (minimal features)
  - Expected: May work with minimal features or return `None`

- ✅ **Normal Dataset**: Does it work with normal data?
  - Tests with 100 packets and full feature set
  - Expected: Returns valid device type and confidence

**Expected Results:**
- All edge cases handled gracefully (no crashes)
- Returns `None` for truly insufficient data
- Works correctly with normal datasets

---

## Test Coverage Summary

| Test | What It Tests | Expected Output |
|------|---------------|-----------------|
| **Basic** | Model loading, classification | `'Doorbell'` or `'Other'` with confidence |
| **Integration** | Full pipeline, routing | Routes to correct expert model |
| **Error Handling** | Edge cases, invalid input | Graceful handling, no crashes |

## Device Type Details

### `'Doorbell'` Class
- **Represents**: Danmini Doorbell IoT device traffic
- **Training Data**: 6 files from `selector-data/Doorbell-data/`
  - `ack`, `benign_traffic`, `scan`, `syn`, `udp`, `udpplain`
- **Characteristics**: 
  - Smaller packet sizes (200-800 bytes typical)
  - More outbound traffic (70% outbound, 30% inbound)
  - Device-specific network patterns
- **Routing**: → `doorbell_model` expert

### `'Other'` Class
- **Represents**: Other IoT devices (CICIOT lab devices)
- **Training Data**: 13 files from `selector-data/Other-devices-data/`
  - Various Mirai botnet attacks
  - Benign traffic from multiple devices
- **Characteristics**:
  - Larger variance in packet sizes (50-2000 bytes)
  - More balanced traffic (50% outbound, 50% inbound)
  - Mixed device patterns
- **Routing**: → Protocol-based experts (DNS, MQTT, etc.) or multi-device models

## How Classification Works

1. **Input**: Packet DataFrame (network traffic features)
2. **Meta-Feature Extraction**: Extract 48 statistical/general meta-features using `pymfe`
3. **Normalization**: Scale features using `StandardScaler`
4. **Classification**: Random Forest predicts `'Doorbell'` or `'Other'`
5. **Output**: Device type + confidence score

## Confidence Thresholds

- **High Confidence** (≥ 0.7): Device selector result is used
- **Low Confidence** (< 0.7): Falls back to port-based routing
- **No Result** (`None`): Falls back to port-based routing

## Example Test Output

```
Test 2: Device selection with sufficient data...
  Packet DataFrame shape: (100, 8)
  ✓ Device type: Other
  ✓ Confidence: 82.00%
```

This shows:
- Input: 100 packets with 8 features
- Output: `'Other'` device type
- Confidence: 82% (high confidence, will be used)

