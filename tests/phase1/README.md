# Phase 1 Tests: Encryption Detection

This directory contains individual test scripts for Phase 1 of the MoE pipeline: **Encryption Detection**.

## Test Structure

Each test is a standalone Python script that can be run independently or as part of the full test suite.

## Available Tests

- **`test_encrypted_tls_traffic.py`**: Tests detection of encrypted TLS traffic on port 443/TCP
- **`test_encrypted_quic_traffic.py`**: Tests detection of encrypted QUIC traffic on port 443/UDP
- **`test_cleartext_dns_traffic.py`**: Tests detection of cleartext DNS traffic on port 53/UDP
- **`test_cleartext_http_traffic.py`**: Tests detection of cleartext HTTP traffic on port 80/TCP
- **`test_unknown_traffic.py`**: Tests handling of unknown traffic on non-standard ports

## Running Tests

### Run a Single Test

```bash
python3 tests/phase1/test_encrypted_tls_traffic.py
```

### Run All Phase 1 Tests

```bash
python3 tests/phase1/run_all_tests.py
```

## Test Script Structure

Each test script follows this structure:

1. **Setup**: Create test data (packet DataFrame, packet bytes)
2. **Execution**: Call `check_encryption()` from `src.moe`
3. **Assertions**: Verify expected results
4. **Output**: Print test status (PASSED/FAILED)

## Expected Behavior

- Encrypted traffic (TLS, QUIC) should return `encrypted=True`
- Cleartext traffic (DNS, HTTP) should return `encrypted=False`
- Unknown traffic should default to `encrypted=False` (can be configured by router policy)

