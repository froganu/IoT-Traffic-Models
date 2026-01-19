# Phase 1 + Phase 2 Integration Tests

This directory contains integration tests that verify the complete pipeline flow from **Phase 1 (Encryption Detection)** through **Phase 2 (Context Selection)**.

## Overview

These tests verify that:
1. Phase 1 correctly identifies encrypted vs cleartext traffic
2. Phase 2 correctly uses both classifiers (Device Classifier + Protocol Classifier)
3. The complete pipeline flow works end-to-end
4. Model selection is correct based on both phases

## Test Structure

```
tests/phase1_phase2/
├── __init__.py
├── README.md
├── test_pipeline_flow.py          # Complete pipeline flow tests
└── test_device_classifier_flow.py  # Device classifier specific flow
```

## Available Tests

### `test_pipeline_flow.py`

**Purpose**: Tests the complete pipeline flow for various traffic types.

**Test Cases**:
1. **Encrypted TLS Traffic**
   - Phase 1: Should detect as encrypted with protocol_type='tls'
   - Phase 2: Should skip both classifiers, route directly to `tls_model`

2. **Cleartext DNS Traffic**
   - Phase 1: Should detect as not encrypted
   - Phase 2: Device classifier → Protocol classifier (DNS) → `dns_model`

3. **Cleartext MQTT Traffic**
   - Phase 1: Should detect as not encrypted
   - Phase 2: Device classifier → Protocol classifier (MQTT) → `mqtt_model`

4. **Cleartext CoAP Traffic**
   - Phase 1: Should detect as not encrypted
   - Phase 2: Device classifier → Protocol classifier (CoAP) → `mqtt_coap_rtsp_model`

5. **Unknown Traffic**
   - Phase 1: Should detect as not encrypted
   - Phase 2: Device classifier → Protocol classifier (UNKNOWN) → Fallback model

**What it verifies**:
- Phase 1 encryption detection works correctly
- Phase 2 device classifier is called
- Phase 2 protocol classifier is called (for non-encrypted traffic)
- Correct model is selected based on both phases
- Complete pipeline flow works end-to-end

### `test_device_classifier_flow.py`

**Purpose**: Tests the pipeline flow specifically for device classifier routing.

**Test Cases**:
1. **Doorbell Device Traffic**
   - Verifies device classifier identifies Doorbell
   - Verifies routing to `doorbell_model` when confidence is high

2. **Other Device Traffic**
   - Verifies device classifier identifies Other
   - Verifies fallthrough to protocol classifier

**What it verifies**:
- Device classifier is called in Phase 2
- Device classifier results affect model selection
- Doorbell traffic routes to `doorbell_model`
- Other device traffic falls through to protocol classifier

## Running Tests

### Run a Single Test

```bash
# Test complete pipeline flow
python3 tests/phase1_phase2/test_pipeline_flow.py

# Test device classifier flow
python3 tests/phase1_phase2/test_device_classifier_flow.py
```

### Run All Integration Tests

```bash
# Run all Phase 1 + Phase 2 tests
python3 tests/phase1_phase2/test_pipeline_flow.py
python3 tests/phase1_phase2/test_device_classifier_flow.py
```

## Expected Output

Each test shows detailed output for both phases:

```
Test: Cleartext DNS Traffic
================================================================================

Phase 1: Encryption Detection
--------------------------------------------------------------------------------
  Encrypted: False (expected: False)
  Protocol Type: None (expected: None)
  ✓ Phase 1 PASSED

Phase 2: Context Selection
--------------------------------------------------------------------------------
  Step 2.1: Device Classifier
    Device Type: None (no specific device identified)

  Step 2.2: Protocol Classifier
    Protocol: DNS
    Confidence: 0.95
    Evidence: dns_header

  Step 2.3: Full Context Selection
    Selected Model: dns_model (expected: dns_model)
  ✓ Phase 2 PASSED

✓ Cleartext DNS Traffic: PASSED
```

## Pipeline Flow

The complete pipeline flow tested:

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Encryption Detection                               │
│   Input: packet_data, packet_bytes, port, protocol         │
│   Output: is_encrypted, protocol_type                      │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │ is_encrypted?                 │
        └───────┬───────────────┬───────┘
                │               │
        ┌───────▼───────┐ ┌─────▼──────────────┐
        │ Encrypted     │ │ Not Encrypted      │
        │               │ │                    │
        │ Route to:     │ │ Phase 2: Context   │
        │ - tls_model   │ │ Selection          │
        │ - quic_model  │ │                    │
        │ - dtls_model  │ │ Step 1: Device     │
        └───────────────┘ │ Classifier         │
                          │                    │
                          │ Step 2: Protocol   │
                          │ Classifier         │
                          │                    │
                          │ Step 3: Model      │
                          │ Selection          │
                          └────────────────────┘
```

## Integration with Other Tests

These integration tests complement:
- **Phase 1 tests** (`tests/phase1/`): Test encryption detection in isolation
- **Phase 2 tests** (`tests/phase2/`): Test context selection in isolation
- **Phase 3 tests** (`tests/phase3/`): Test complete pipeline including C2 detection

## Dependencies

- `pandas` - For DataFrame operations
- `numpy` - For numerical operations
- `src.moe` - MoE integration module
- `src.context_selection_models` - Device and protocol classifiers

## Notes

- Device classifier may return `None` if insufficient data or patterns don't match
- Protocol classifier may return `UNKNOWN` for TCP protocols that need reassembly
- Fallback to port-based routing is acceptable when classifiers are unavailable
- Tests verify the flow works correctly even when classifiers return `None` or `UNKNOWN`

