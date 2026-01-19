# Phase 2 Tests: Context Selection

This directory contains tests for Phase 2 of the MoE pipeline: **Context Selection** (Model Selection).

Phase 2 uses **two classifiers** for non-encrypted traffic:
1. **Device Classifier**: Identifies device type (Doorbell vs Other)
2. **Protocol Classifier**: Identifies protocol (DNS, MQTT, CoAP, RTSP)

## Test Structure

Each test is a standalone Python script that can be run independently or as part of the full test suite.

## Available Tests

### Device Classifier Tests

- **`test_device_selector_basic.py`**: Tests basic device selector functionality
  - Model loading
  - Device classification with sufficient data
  - Handling of small datasets
  
- **`test_device_selector_integration.py`**: Tests device selector integration with MoE pipeline
  - Full pipeline: Phase 1 (encryption detection) → Phase 2 (context selection)
  - Verifies device selector is used for non-encrypted traffic
  - Tests fallback to protocol classifier when device selector unavailable

- **`test_device_selector_error_handling.py`**: Tests error handling and edge cases
  - Empty DataFrames
  - Very small datasets
  - Missing dependencies
  - Invalid data

### Protocol Classifier Tests

- **`test_protocol_classifier_integration.py`**: Tests protocol classifier integration
  - DNS protocol detection
  - MQTT protocol detection
  - CoAP protocol detection
  - RTSP protocol detection
  - Verifies protocol classifier is used in Phase 2

### Context Selection Tests (Full Pipeline)

- **`test_encrypted_tls_context_selection.py`**: Tests context selection for encrypted TLS traffic
  - Skips both classifiers (encrypted traffic routes directly to TLS model)

- **`test_cleartext_dns_context_selection.py`**: Tests context selection for cleartext DNS traffic
  - Verifies both device classifier and protocol classifier are called
  - Verifies protocol classifier identifies DNS
  - Verifies DNS model is selected

- **`test_cleartext_mqtt_context_selection.py`**: Tests context selection for cleartext MQTT traffic
  - Verifies both device classifier and protocol classifier are called
  - Verifies protocol classifier identifies MQTT (may need TCP reassembly)
  - Verifies MQTT model is selected

- **`test_unknown_context_selection.py`**: Tests context selection for unknown traffic
  - Verifies both classifiers are attempted
  - Verifies fallback to port-based routing works

## Running Tests

### Run a Single Test

```bash
python3 tests/phase2/test_device_selector_basic.py
```

### Run All Phase 2 Tests

```bash
python3 tests/phase2/run_all_tests.py
```

## Phase 2 Classifier Flow

For **non-encrypted traffic**, Phase 2 uses both classifiers in sequence:

1. **Device Classifier** (First Priority)
   - Attempts to identify device type: `Doorbell` vs `Other`
   - If `Doorbell` with high confidence → routes to `doorbell_model`
   - If `Other` or low confidence → continues to protocol classifier

2. **Protocol Classifier** (Second Priority)
   - Attempts to identify protocol: `DNS`, `MQTT`, `CoAP`, `RTSP`, `OTHER`, `UNKNOWN`
   - Uses DPI signatures (not just ports)
   - Routes to appropriate model based on protocol

3. **Port-Based Fallback** (Last Resort)
   - Only used if both classifiers fail or are unavailable
   - Simple port heuristics (53 → DNS, 1883 → MQTT, etc.)

For **encrypted traffic**, Phase 2 skips both classifiers and routes directly to TLS/QUIC/DTLS models.

## Device Classifier Testing

The device selector tests focus on:

1. **Model Loading**: Verifies trained models can be loaded
2. **Classification**: Tests device type prediction (Doorbell vs Other)
3. **Integration**: Verifies device selector is used in the MoE pipeline
4. **Error Handling**: Tests graceful handling of edge cases

### Dependencies

Device selector tests require:
- `joblib` - For loading .pkl model files
- `scikit-learn` - For RandomForestClassifier and StandardScaler
- `pymfe` - For meta-feature extraction

If dependencies are missing, tests will skip gracefully (not fail).

### Expected Behavior

- **With dependencies**: Device selector classifies traffic and routes to appropriate expert
- **Without dependencies**: System falls back to protocol classifier
- **Small datasets**: Device selector may return None (expected behavior)
- **Error cases**: Device selector handles gracefully without crashing

## Protocol Classifier Testing

The protocol classifier tests verify:

1. **Protocol Detection**: DNS, MQTT, CoAP, RTSP identification
2. **Integration**: Protocol classifier is called in Phase 2
3. **Model Routing**: Correct model is selected based on protocol
4. **Fallback**: Port-based routing works when classifier unavailable

### Expected Behavior

- **DNS/CoAP (UDP)**: High confidence from single packet
- **MQTT/RTSP (TCP)**: May need TCP reassembly, may return UNKNOWN
- **Unknown protocols**: Returns UNKNOWN or OTHER
- **Integration**: Routes to correct model (dns_model, mqtt_model, etc.)

## Test Script Structure

Each test script follows this structure:

1. **Setup**: Create test data (packet DataFrame)
2. **Execution**: Call device selector or `select_ai_model()` from `src.moe`
3. **Assertions**: Verify expected results
4. **Output**: Print test status (PASSED/FAILED/SKIPPED)

