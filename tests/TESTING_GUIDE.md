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

## Quick Start

```bash
# Run all phases
python tests/run_tests.py --all-phases

# Run specific phase
python tests/run_tests.py --phase 1

# Run integration tests
python tests/run_tests.py --integration
```

## Phase 1: Encryption Detection

**Purpose**: Verify that the system correctly identifies encrypted vs cleartext traffic.

**Tests**:
- `test_encrypted_tls_traffic` - TLS on port 443
- `test_encrypted_quic_traffic` - QUIC on UDP/443
- `test_cleartext_dns_traffic` - DNS on port 53
- `test_cleartext_http_traffic` - HTTP on port 80
- `test_unknown_traffic` - Unknown ports/protocols

**What it validates**:
- Encryption detection logic
- Protocol type identification (TLS, QUIC, DTLS)
- Handling of unknown traffic

**Example**:
```python
# Phase 1 test
is_encrypted, protocol_type = check_encryption(
    packet_data, port=443, protocol='tcp', packet_bytes=tls_bytes
)
assert is_encrypted == True
assert protocol_type == 'tls'
```

## Phase 2: Context Selection

**Purpose**: Verify that the correct expert/model is selected based on encryption status and context.

**Tests**:
- `test_encrypted_tls_context_selection` - TLS → tls_model
- `test_cleartext_dns_context_selection` - DNS → dns_model
- `test_cleartext_mqtt_context_selection` - MQTT → mqtt_model
- `test_unknown_context_selection` - Unknown → default_model

**What it validates**:
- Model selection logic
- Routing based on encryption status
- Routing based on protocol/port

**Example**:
```python
# Phase 1: Encryption detection
is_encrypted, protocol_type = check_encryption(...)

# Phase 2: Context selection
model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
assert model_name == 'tls_model'
```

## Phase 3: C2 Detection

**Purpose**: Verify end-to-end C2 detection with confidence scores.

**Tests**:
- `test_encrypted_tls_c2_detection` - Full pipeline for TLS
- `test_cleartext_dns_c2_detection` - Full pipeline for DNS
- `test_cleartext_mqtt_c2_detection` - Full pipeline for MQTT
- `test_unknown_traffic_c2_detection` - Full pipeline for unknown

**What it validates**:
- Complete pipeline execution
- C2 prediction output
- Confidence scores
- All phases working together

**Example**:
```python
# Full pipeline
result = detect_c2(packet_data, port=443, protocol='tcp', packet_bytes=tls_bytes)

# Validate all phases
assert result['is_encrypted'] == True  # Phase 1
assert result['model_used'] == 'tls_model'  # Phase 2
assert 'is_c2' in result  # Phase 3
assert 'probability' in result  # Phase 3
```

## Test Fixtures

Reusable test data is provided in `test_fixtures.py`:

```python
from tests.test_fixtures import TestFixtures

# Create packet bytes
tls_bytes = TestFixtures.create_tls_packet_bytes()
dns_bytes = TestFixtures.create_dns_packet_bytes()

# Create packet DataFrame
packet_df = TestFixtures.create_packet_dataframe(
    n_packets=5,
    port=443,
    protocol='tcp'
)

# Create complete scenario
scenario = TestFixtures.create_flow_scenario('tls', n_packets=5)
```

## Running Tests

### Option 1: Test Runner Script (Recommended)

```bash
# All phases sequentially
python tests/run_tests.py --all-phases

# Specific phase
python tests/run_tests.py --phase 1

# Integration (all together)
python tests/run_tests.py --integration

# Verbosity control
python tests/run_tests.py --phase 1 --verbosity 0  # Quiet
python tests/run_tests.py --phase 1 --verbosity 2  # Verbose
```

### Option 2: unittest

```bash
# All tests
python -m unittest discover tests

# Specific test class
python -m unittest tests.test_pipeline.Phase1EncryptionDetectionTests

# Specific test
python -m unittest tests.test_pipeline.Phase1EncryptionDetectionTests.test_encrypted_tls_traffic
```

## Test Results

Tests record results using `record_test_result()`:

```python
self.record_test_result(phase, test_name, {
    'is_encrypted': is_encrypted,
    'protocol_type': protocol_type,
    'passed': True
})
```

Results are stored in `self.test_results` and can be used for reporting.

## Adding New Tests

### 1. Add to Existing Phase

```python
class Phase1EncryptionDetectionTests(PipelineTestBase):
    def test_new_protocol(self):
        """Test new protocol detection."""
        # Your test code
        self.record_test_result(1, 'new_protocol', {...})
```

### 2. Create New Test Class

```python
class Phase1CustomTests(PipelineTestBase):
    """Custom Phase 1 tests."""
    def test_custom(self):
        """Custom test."""
        # Your test code
```

Then add to test runner:
```python
loader = unittest.TestLoader()
tests = loader.loadTestsFromTestCase(Phase1CustomTests)
suite.addTests(tests)
```

## Debugging

### Verbose Output

```bash
python tests/run_tests.py --phase 1 --verbosity 2
```

### Python Debugger

```bash
python -m pdb -m unittest tests.test_pipeline.Phase1EncryptionDetectionTests.test_encrypted_tls_traffic
```

### Print Debugging

Add print statements in tests:
```python
def test_something(self):
    result = detect_c2(...)
    print(f"Debug: {result}")  # Will show in test output
    self.assert...
```

## Test Coverage

```bash
# Install coverage
pip install coverage

# Run with coverage
coverage run -m unittest discover tests

# View report
coverage report

# HTML report
coverage html
open htmlcov/index.html
```

## CI/CD Integration

For continuous integration:

```bash
# Exit code 0 on success, 1 on failure
python tests/run_tests.py --all-phases
```

Example GitHub Actions:

```yaml
- name: Run Tests
  run: python tests/run_tests.py --all-phases
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

## Troubleshooting

### Import Errors

```bash
# Make sure you're in the project root
cd /path/to/IoT-Traffic-Models
python tests/run_tests.py --phase 1
```

### Module Not Found

```bash
# Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python tests/run_tests.py --phase 1
```

### Tests Failing

1. Check if encryption_detector module is available
2. Verify moe_integration.py functions are implemented
3. Check test output for specific error messages
4. Run with verbose output: `--verbosity 2`

