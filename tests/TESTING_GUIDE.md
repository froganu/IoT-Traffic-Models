# Testing Guide - MoE Pipeline

## Overview

The MoE pipeline is tested in three phases, each building on the previous:

1. **Phase 1: Encryption Detection** - Tests if traffic is encrypted or not
2. **Phase 2: Context Selection** - Tests which expert/model is selected
3. **Phase 3: C2 Detection** - Tests end-to-end C2 detection with confidence

## Test Architecture

```
Pipeline Flow:
┌─────────────────┐
│  Phase 1 Tests  │ → Encryption Detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Phase 2 Tests  │ → Encryption Detection → Context Selection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Phase 3 Tests  │ → Encryption Detection → Context Selection → C2 Detection
└─────────────────┘
```

## Test Structure

Each phase has its own directory with individual test scripts:

```
tests/
├── phase1/          # Phase 1: Encryption Detection
│   ├── test_encrypted_tls_traffic.py
│   ├── test_encrypted_quic_traffic.py
│   ├── test_cleartext_dns_traffic.py
│   ├── test_cleartext_http_traffic.py
│   ├── test_unknown_traffic.py
│   └── run_all_tests.py
├── phase2/          # Phase 2: Context Selection
│   ├── test_encrypted_tls_context_selection.py
│   ├── test_cleartext_dns_context_selection.py
│   ├── test_cleartext_mqtt_context_selection.py
│   ├── test_unknown_context_selection.py
│   └── run_all_tests.py
└── phase3/          # Phase 3: C2 Detection
    ├── test_encrypted_tls_c2_detection.py
    ├── test_cleartext_dns_c2_detection.py
    ├── test_cleartext_mqtt_c2_detection.py
    ├── test_unknown_traffic_c2_detection.py
    └── run_all_tests.py
```

## Quick Start

```bash
# Run a single Phase 1 test
python3 tests/phase1/test_encrypted_tls_traffic.py

# Run all Phase 1 tests
python3 tests/phase1/run_all_tests.py

# Run all Phase 2 tests
python3 tests/phase2/run_all_tests.py

# Run all Phase 3 tests
python3 tests/phase3/run_all_tests.py
```

## Phase 1: Encryption Detection

**Purpose**: Verify that the system correctly identifies encrypted vs cleartext traffic.

**Tests**:
- `test_encrypted_tls_traffic.py` - TLS on port 443
- `test_encrypted_quic_traffic.py` - QUIC on UDP/443
- `test_cleartext_dns_traffic.py` - DNS on port 53
- `test_cleartext_http_traffic.py` - HTTP on port 80
- `test_unknown_traffic.py` - Unknown ports/protocols

**What it validates**:
- Encryption detection logic
- Protocol type identification (TLS, QUIC, DTLS)
- Handling of unknown traffic

**Example**:
```bash
# Run a single test
python3 tests/phase1/test_encrypted_tls_traffic.py

# Run all Phase 1 tests
python3 tests/phase1/run_all_tests.py
```

## Phase 2: Context Selection

**Purpose**: Verify that the correct expert/model is selected based on encryption status and context.

**Tests**:
- `test_encrypted_tls_context_selection.py` - TLS → tls_model
- `test_cleartext_dns_context_selection.py` - DNS → dns_model
- `test_cleartext_mqtt_context_selection.py` - MQTT → mqtt_model
- `test_unknown_context_selection.py` - Unknown → default_model

**What it validates**:
- Model selection logic
- Routing based on encryption status
- Routing based on protocol/port

**Example**:
```bash
# Run a single test
python3 tests/phase2/test_encrypted_tls_context_selection.py

# Run all Phase 2 tests
python3 tests/phase2/run_all_tests.py
```

## Phase 3: C2 Detection

**Purpose**: Verify end-to-end C2 detection with confidence scores.

**Tests**:
- `test_encrypted_tls_c2_detection.py` - Full pipeline for TLS
- `test_cleartext_dns_c2_detection.py` - Full pipeline for DNS
- `test_cleartext_mqtt_c2_detection.py` - Full pipeline for MQTT
- `test_unknown_traffic_c2_detection.py` - Full pipeline for unknown

**What it validates**:
- Complete pipeline execution
- C2 prediction output
- Confidence scores
- All phases working together

**Example**:
```bash
# Run a single test
python3 tests/phase3/test_encrypted_tls_c2_detection.py

# Run all Phase 3 tests
python3 tests/phase3/run_all_tests.py
```

## Running Tests

### Option 1: Individual Test Scripts (Recommended)

Each test is a standalone script that can be run independently:

```bash
# Run a specific test
python3 tests/phase1/test_encrypted_tls_traffic.py

# Run all tests in a phase
python3 tests/phase1/run_all_tests.py
```

### Option 2: Run All Phases Manually

```bash
# Phase 1
python3 tests/phase1/run_all_tests.py

# Phase 2
python3 tests/phase2/run_all_tests.py

# Phase 3
python3 tests/phase3/run_all_tests.py
```

## Adding New Tests

### 1. Create a New Test Script

Create a new file in the appropriate phase directory:

```python
#!/usr/bin/env python3
"""
Phase 1 Test: Your Test Name

Description of what this test does.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from src.moe import check_encryption  # Import functions you need


def create_packet_dataframe(port=443, protocol='tcp'):
    """Create test packet DataFrame."""
    # Your data creation logic
    return pd.DataFrame({...})


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 1 Test: Your Test Name")
    print("=" * 80)
    print()
    
    # Your test logic here
    packet_data = create_packet_dataframe()
    result = check_encryption(...)
    
    # Assertions
    print("Assertions:")
    try:
        assert result == expected, f"Expected {expected}, got {result}"
        print("  ✓ Test passed")
        print()
        print("=" * 80)
        print("TEST PASSED ✓")
        print("=" * 80)
        return 0
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
        print()
        print("=" * 80)
        print("TEST FAILED ✗")
        print("=" * 80)
        return 1


if __name__ == '__main__':
    sys.exit(main())
```

### 2. Make Script Executable

```bash
chmod +x tests/phase1/your_new_test.py
```

### 3. Test Scripts Are Automatically Discovered

The `run_all_tests.py` script in each phase directory automatically finds and runs all `test_*.py` scripts.

## Debugging

### Print Output

Each test script prints detailed output including:
- Test input
- Intermediate results
- Final assertions
- Pass/Fail status

### Run Individual Test

```bash
# Run a single test for debugging
python3 tests/phase1/test_encrypted_tls_traffic.py
```

### Check Exit Code

```bash
# Exit code 0 = pass, 1 = fail
python3 tests/phase1/test_encrypted_tls_traffic.py
echo $?  # 0 if passed, 1 if failed
```

## Expected Behavior

### Phase 1 (Encryption Detection)
- ✅ TLS on 443 → `is_encrypted=True`, `protocol_type='tls'`
- ✅ DNS on 53 → `is_encrypted=False`, `protocol_type=None`
- ✅ Unknown → `is_encrypted=False` (default)

### Phase 2 (Context Selection)
- ✅ Encrypted TLS → `model_name='tls_model'`
- ✅ Cleartext DNS → `model_name='dns_model'`
- ✅ Cleartext MQTT → `model_name='mqtt_model'`

### Phase 3 (C2 Detection)
- ✅ Full pipeline executes
- ✅ All phases complete
- ✅ `is_c2` field present (may be None if models not loaded)
- ✅ `probability` field present (may be None if models not loaded)

## Notes

- **Skeleton State**: Some tests may have `is_c2=None` if models aren't implemented yet. This is expected.
- **Model Loading**: Phase 3 tests validate the pipeline structure, not actual model predictions (until models are implemented).
- **Test Data**: All tests use synthetic data. Real PCAP files can be added for integration testing.
- **Standalone Scripts**: Each test is independent and can be run without test runners.

## Troubleshooting

### Import Errors

```bash
# Make sure you're in the project root
cd /path/to/IoT-Traffic-Models
python3 tests/phase1/test_encrypted_tls_traffic.py
```

### Module Not Found

```bash
# The test scripts automatically add the project root to sys.path
# If issues persist, check that src/ directory exists
ls -la src/
```

### Tests Failing

1. Check if encryption_detector module is available
2. Verify moe integration functions are implemented
3. Check test output for specific error messages
4. Run individual tests to isolate issues
