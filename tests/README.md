# MoE Pipeline Testing Infrastructure

This directory contains the testing infrastructure for the MoE IoT C2 Detection pipeline.

## Test Structure

The pipeline is tested in three phases:

### Phase 1: Encryption Detection
Tests the first phase: determining if traffic is encrypted or not.
- Encrypted traffic (TLS, QUIC, DTLS)
- Cleartext traffic (DNS, HTTP, MQTT, CoAP, RTSP)
- Unknown traffic handling

### Phase 2: Context Selection
Tests the second phase: selecting which expert/model to use based on encryption status.
- Runs Phase 1 first, then tests context selection
- Tests model selection for encrypted contexts (TLS model)
- Tests model selection for cleartext contexts (DNS, MQTT, etc.)

### Phase 3: C2 Detection
Tests the third phase: detecting if traffic is C2 attack or not with confidence.
- Runs full pipeline: Phase 1 → Phase 2 → Phase 3
- Tests end-to-end C2 detection
- Validates confidence scores

## Running Tests

### Quick Start

```bash
# Run all phases sequentially
python tests/run_tests.py --all-phases

# Run specific phase
python tests/run_tests.py --phase 1  # Encryption detection
python tests/run_tests.py --phase 2  # Context selection
python tests/run_tests.py --phase 3  # C2 detection

# Run integration tests (all phases together)
python tests/run_tests.py --integration

# Run with different verbosity
python tests/run_tests.py --phase 1 --verbosity 0  # Quiet
python tests/run_tests.py --phase 1 --verbosity 2  # Verbose
```

### Using unittest directly

```bash
# Run all tests
python -m unittest discover tests

# Run specific test class
python -m unittest tests.test_pipeline.Phase1EncryptionDetectionTests

# Run specific test
python -m unittest tests.test_pipeline.Phase1EncryptionDetectionTests.test_encrypted_tls_traffic
```

## Test Files

- **test_pipeline.py**: Main pipeline tests (Phase 1, 2, 3)
- **test_fixtures.py**: Test fixtures and utilities
- **run_tests.py**: Test runner script with convenient interface

## Test Fixtures

The `TestFixtures` class provides reusable test data:

```python
from tests.test_fixtures import TestFixtures

# Create packet bytes
tls_bytes = TestFixtures.create_tls_packet_bytes()
dns_bytes = TestFixtures.create_dns_packet_bytes()

# Create packet DataFrame
packet_df = TestFixtures.create_packet_dataframe(
    n_packets=5,
    port=443,
    protocol='tcp',
    include_tls_features=True
)

# Create complete flow scenario
scenario = TestFixtures.create_flow_scenario('tls', n_packets=5)
```

## Adding New Tests

### Adding a Phase 1 Test

```python
class Phase1EncryptionDetectionTests(PipelineTestBase):
    def test_my_new_encryption_test(self):
        """Test description."""
        packet_data = self.create_packet_dataframe(port=443, protocol='tcp')
        packet_bytes = self.create_tls_packet_bytes()
        
        is_encrypted, protocol_type = check_encryption(
            packet_data, port=443, protocol='tcp', packet_bytes=packet_bytes
        )
        
        self.assertTrue(is_encrypted)
        self.record_test_result(1, 'my_new_test', {
            'is_encrypted': is_encrypted,
            'passed': is_encrypted
        })
```

### Adding a Phase 2 Test

```python
class Phase2ContextSelectionTests(PipelineTestBase):
    def test_my_new_context_test(self):
        """Test description."""
        # Phase 1: Encryption detection
        packet_data = self.create_packet_dataframe(port=443, protocol='tcp')
        is_encrypted, protocol_type = check_encryption(...)
        
        # Phase 2: Context selection
        model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
        
        self.assertEqual(model_name, 'expected_model')
        self.record_test_result(2, 'my_new_test', {...})
```

### Adding a Phase 3 Test

```python
class Phase3C2DetectionTests(PipelineTestBase):
    def test_my_new_c2_test(self):
        """Test description."""
        # Full pipeline
        packet_data = self.create_packet_dataframe(port=443, protocol='tcp')
        result = detect_c2(packet_data, port=443, protocol='tcp')
        
        # Validate all phases
        self.assertTrue(result['is_encrypted'])
        self.assertEqual(result['model_used'], 'tls_model')
        self.assertIn('is_c2', result)
        self.record_test_result(3, 'my_new_test', {...})
```

## Test Results

Tests record results using `record_test_result()` which stores:
- Phase number
- Test name
- Result dictionary with test-specific data

Results can be accessed via `self.test_results` in test classes.

## Continuous Integration

For CI/CD pipelines:

```bash
# Run all tests and exit with code 0 on success, 1 on failure
python tests/run_tests.py --all-phases

# Or use unittest
python -m unittest discover tests -v
```

## Debugging Tests

To debug a failing test:

```bash
# Run with verbose output
python tests/run_tests.py --phase 1 --verbosity 2

# Run specific test with Python debugger
python -m pdb -m unittest tests.test_pipeline.Phase1EncryptionDetectionTests.test_encrypted_tls_traffic
```

## Test Coverage

To check test coverage (requires coverage.py):

```bash
pip install coverage
coverage run -m unittest discover tests
coverage report
coverage html  # Generate HTML report
```

## Notes

- Each phase test runs the full pipeline from the beginning
- Phase 2 tests include Phase 1 (encryption detection)
- Phase 3 tests include Phase 1 and Phase 2 (full pipeline)
- Tests use synthetic data - real PCAP files can be added for integration testing
- Model loading/prediction tests may return None if models aren't implemented yet (expected in skeleton)

