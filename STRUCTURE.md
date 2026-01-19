# Project Structure

## Professional Industry-Standard Organization

```
IoT-Traffic-Models/
├── src/                              # Source code (main package)
│   ├── moe/                          # MoE core system
│   │   ├── __init__.py              # Package exports
│   │   ├── integration.py           # MoE integration framework
│   │   └── accuracy_table.py        # Accuracy tracking
│   └── encryption_detector/          # Encryption detection module
│       ├── __init__.py              # Package exports
│       ├── detector.py              # Main detection logic
│       ├── pcap_reader.py           # PCAP parsing & flow reconstruction
│       ├── signatures.py            # Protocol signatures
│       ├── utils.py                 # Utilities
│       ├── cli.py                   # CLI interface
│       ├── README.md                # Module documentation
│       └── tests/                   # Encryption detector tests
│           ├── __init__.py
│           ├── test_signatures.py
│           └── test_detector_smoke.py
│
├── tests/                            # Test suite
│   ├── __init__.py
│   ├── test_pipeline.py             # Pipeline tests (Phase 1, 2, 3)
│   ├── test_fixtures.py             # Test fixtures
│   ├── run_tests.py                 # Test runner
│   ├── README.md                    # Test documentation
│   └── TESTING_GUIDE.md             # Testing guide
│
├── docs/                             # Documentation
│   ├── PROJECT_SUMMARY.md           # Comprehensive project docs
│   ├── ARCHITECTURE_AND_ASSUMPTIONS.md
│   ├── extending12to13_README.md    # TLS 1.3 detection docs
│   └── QUICKSTART.md                # Quick start guide
│
├── trained_models/                   # Trained AI models
│   ├── TLS/                         # TLS 1.3 C2 detection models
│   ├── DNS/                         # DNS-based C2 detection
│   ├── MQTT_COAP_RTSP/             # Multi-protocol IoT detection
│   ├── Danmini_Doorbell_Device/    # Device-specific detection
│   └── Multiple_IoT_device_types/   # Multi-device detection
│
├── Andrea/                           # Team member work (preserved)
├── Hasan/                            # Team member work (preserved)
├── Ivan/                             # Team member work (preserved)
├── Jaume/                            # Team member work (preserved)
├── Pol/                              # Team member work (preserved)
│
├── example_usage.py                  # Example usage scripts
├── requirements.txt                  # Python dependencies
├── setup.py                          # Package setup script
└── README.md                         # Main project README
```

## Import Paths

### Before (Old Structure)
```python
from moe_integration import detect_c2
from accuracy_table import AccuracyTable
from encryption_detector import analyze_packet
```

### After (New Structure)
```python
from src.moe import detect_c2, AccuracyTable
from src.encryption_detector import analyze_packet
```

## Key Changes

1. **Source Code Organization**
   - All source code moved to `src/` directory
   - `moe/` package for core MoE system
   - `encryption_detector/` package for encryption detection

2. **Documentation Organization**
   - All documentation moved to `docs/` directory
   - Keeps root directory clean

3. **Test Organization**
   - Tests remain in `tests/` at root level (standard practice)
   - Encryption detector has its own tests in `src/encryption_detector/tests/`

4. **Team Member Folders**
   - Preserved as-is (Andrea, Hasan, Ivan, Jaume, Pol)

5. **Configuration Files**
   - `setup.py` added for proper package installation
   - `requirements.txt` remains at root
   - `README.md` updated with new structure

## Installation

```bash
# Install in development mode
pip install -e .

# Or add src to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

## Running Tests

```bash
# From project root
python tests/run_tests.py --all-phases

# Or with unittest
python -m unittest discover tests
```

## Running Examples

```bash
# From project root
python example_usage.py
```

## Benefits of New Structure

1. **Professional**: Follows Python packaging best practices
2. **Scalable**: Easy to add new modules/packages
3. **Maintainable**: Clear separation of concerns
4. **Testable**: Tests clearly separated from source
5. **Documented**: Documentation organized in one place
6. **Installable**: Can be installed as a package via setup.py

