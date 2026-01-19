# IoT-Traffic-Models: Mixture of Experts for C2 Traffic Detection

## Overview

This project implements a **Mixture of Experts (MoE)** system for detecting Command and Control (C2) traffic across different network contexts, including both encrypted and non-encrypted traffic.

## Project Structure

```
IoT-Traffic-Models/
├── src/                            # Source code
│   ├── moe/                        # MoE core system
│   │   ├── __init__.py
│   │   ├── integration.py         # MoE integration framework
│   │   └── accuracy_table.py      # Accuracy table management
│   └── encryption_detector/       # Encryption detection module
│       ├── __init__.py
│       ├── detector.py            # Main detection logic
│       ├── pcap_reader.py         # PCAP parsing
│       ├── signatures.py          # Protocol signatures
│       ├── utils.py               # Utilities
│       ├── cli.py                 # CLI interface
│       └── tests/                 # Encryption detector tests
├── tests/                          # Test suite
│   ├── test_pipeline.py           # Pipeline tests (Phase 1, 2, 3)
│   ├── test_fixtures.py           # Test fixtures
│   └── run_tests.py               # Test runner
├── docs/                           # Documentation
│   ├── PROJECT_SUMMARY.md         # Comprehensive project docs
│   ├── ARCHITECTURE_AND_ASSUMPTIONS.md
│   ├── extending12to13_README.md  # TLS 1.3 detection docs
│   └── QUICKSTART.md              # Quick start guide
├── trained_models/                 # Trained models for all contexts
│   ├── TLS/                       # TLS 1.3 C2 detection models
│   ├── DNS/                       # DNS-based C2 detection
│   ├── MQTT_COAP_RTSP/           # Multi-protocol IoT detection
│   ├── Danmini_Doorbell_Device/  # Device-specific detection
│   └── Multiple_IoT_device_types/ # Multi-device detection
├── Andrea/                         # Team member work
├── Hasan/                          # TLS 1.3 work
├── Ivan/                           # IoT threat detection
├── Jaume/                          # DNS-based C2 detection
├── Pol/                            # Multi-protocol IoT detection
├── example_usage.py                # Example usage scripts
├── requirements.txt                # Python dependencies
├── setup.py                        # Package setup
└── README.md                       # This file
```

## Contexts

### Encrypted Traffic
- **TLS 1.2 to TLS 1.3-enabled Malware** (Hasan)
  - Behavior-based C2 detection
  - Works for both TLS 1.2 and TLS 1.3
  - See `extending12to13_README.md` for details

### Non-Encrypted Traffic
- **MQTT, COAP:v1, RTSP** (Pol)
  - Multi-protocol IoT botnet detection
- **Danmini Doorbell Device** (Ivan/Andrea)
  - Device-specific Mirai botnet detection
- **CICIOT Lab** (Multiple IoT devices)
  - Multi-device IoT botnet detection
- **DNS-Based Command & Control** (Jaume)
  - DNS-based C2 detection from IoT23 dataset

## MoE Architecture

### Flow

1. **Encryption Detection** (Deterministic)
   - Checks if traffic is encrypted (TLS/QUIC/DTLS) or not encrypted

2. **If Encrypted:**
   - Route to **TLS Expert Model**
   - Detects C2 traffic using behavior-based features
   - Can distinguish: QUIC vs TLS vs DTLS
   - Can detect encrypted DNS (DoH/DoT)

3. **If Not Encrypted:**
   - Use **AI Selector Model** to choose expert
   - Experts include:
     - Protocol-based: MQTT, COAP, RTSP, DNS
     - Device-based: Danmini Doorbell, CICIOT devices

### Infrastructure Components

- ✅ **Accuracy Table**: Tracks performance metrics per context/model
- ✅ **Trained Models**: All AI models stored in `trained_models/`
- ✅ **Best 2 Models**: Top 2 models per context identified
- 🔄 **Light Retraining DPI**: Enhancement with Deep Packet Inspection (future work)

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# On macOS, XGBoost requires:
brew install libomp
```

### Usage (Skeleton)

This is a **skeleton framework**. Implement the TODO sections:

```python
from src.moe import detect_c2

# Detect C2 traffic
result = detect_c2(flow_data, port=443, protocol='tcp')
print(f"Is C2: {result['is_c2']}")
```

**To implement:**
1. `check_encryption()` - Encryption detection logic
2. `select_ai_model()` - Model selection based on context
3. `load_model()` - Load trained models
4. `predict_c2()` - Run predictions

See `example_usage.py` for more examples.

### Accuracy Table

```python
from src.moe import AccuracyTable

# Initialize and view accuracy table
acc_table = AccuracyTable()
acc_table.print_summary()

# Get best 2 models per context
best_models = acc_table.get_all_best_models(n=2, metric='f1')
```

## Documentation

- **docs/PROJECT_SUMMARY.md**: Comprehensive project documentation with all details
- **docs/extending12to13_README.md**: TLS 1.3 C2 detection implementation details
- **docs/ARCHITECTURE_AND_ASSUMPTIONS.md**: Architecture and assumptions
- **docs/README.md**: Documentation index
- **src/moe/integration.py**: MoE system implementation with docstrings
- **src/moe/accuracy_table.py**: Accuracy tracking and management

## Key Features

- ✅ **Behavior-Only Detection**: No payload inspection required
- ✅ **Cross-Protocol Generalization**: TLS 1.2 trained models work on TLS 1.3
- ✅ **Multiple Contexts**: Supports various IoT and network protocols
- ✅ **Modular Design**: Easy to add new experts and contexts
- ✅ **Performance Tracking**: Comprehensive accuracy table system

## Key Concepts

### Behavior-Only Features
- **Allowed**: Packet sizes, timing, direction, port numbers
- **Not Allowed**: Payload content, DNS domain names, MQTT topics

### Model Selection
- **Best 2 models** per context are used
- For TLS: XGBoost + Random Forest
- Aggregation via majority voting

## Troubleshooting

### Models Not Found
```bash
# Ensure models are in trained_models/TLS/
ls trained_models/TLS/
```

### Import Errors
```bash
# Check dependencies
pip install -r requirements.txt

# Make sure src is in PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### XGBoost Issues (macOS)
```bash
brew install libomp
```

## Model Performance

### TLS Context (Best 2 Models)
1. **XGBoost**: 99.80% TNR, 97.41% TPR ⭐
2. **Random Forest**: 98.20% TNR, 96.07% TPR

See `accuracy_table.py` for full performance metrics.

## Next Steps

1. Integrate teammates' non-encrypted expert models
2. Implement selector model for non-encrypted routing
3. Add DPI enhancement features
4. Create unified API for all contexts

## Contact & References

See `PROJECT_SUMMARY.md` for detailed references and citations.

---

**Note**: This is an active research project. Models and implementations are being continuously improved.
