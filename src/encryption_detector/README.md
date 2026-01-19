# Encryption Detector Module

Deterministic packet-level encryption classifier for MoE IoT C2 Detection system.

## Overview

This module provides encryption detection at the packet/flow level, outputting binary decisions (encrypted vs not_encrypted) with internal evidence and confidence scores. It is designed to work with both full-payload and truncated PCAP captures.

## Features

- **Deterministic detection** (no ML) using protocol signatures and heuristics
- **Packet-level processing** from PCAP files or raw packet bytes
- **Flow reconstruction** using 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol)
- **Robust to truncation** - handles truncated captures gracefully
- **Multiple evidence types** - handshake, record_framing, dpi_proto, port_heuristic, entropy, insufficient
- **Confidence scores** - 0.0-1.0 for each detection

## Installation

```bash
# Install dependencies (if needed)
pip install -r requirements.txt
```

## Usage

### Python API

```python
from encryption_detector import analyze_pcap, analyze_packet

# Analyze PCAP file
results = analyze_pcap('traffic.pcap')
for result in results:
    print(f"Flow {result.flow_id}: encrypted={result.encrypted}, "
          f"confidence={result.confidence:.2f}")

# Analyze single packet
packet_bytes = b'\x16\x03\x03\x00\x05...'  # TLS packet
result = analyze_packet(packet_bytes, port=443, protocol='tcp')
print(f"Encrypted: {result.encrypted}, Confidence: {result.confidence}")
```

### Command Line

```bash
# Analyze PCAP file
python -m encryption_detector.cli --pcap traffic.pcap --out results.csv

# Analyze single packet
python -m encryption_detector.cli --packet packet.bin --port 443 --protocol tcp --out result.json

# Export as JSON
python -m encryption_detector.cli --pcap traffic.pcap --out results.json --format json
```

## Detection Rules (Priority Order)

### 1. High-Confidence Encrypted (Protocol Framing)
- **TLS**: Detect TLS record headers in TCP payload
  - Content type, version, length validation
  - Handshake detection (ClientHello/ServerHello)
  - Confidence: 0.95-0.98
- **DTLS**: Detect DTLS record headers in UDP payload
  - Similar to TLS but with epoch/sequence fields
  - Confidence: 0.95
- **QUIC**: Detect QUIC long-header in UDP payload
  - Long-header bit, version, CID validation
  - Confidence: 0.90

### 2. High-Confidence Cleartext (Protocol Signatures)
- **DNS**: DNS header + question parsing
- **HTTP**: HTTP method/version strings
- **MQTT**: MQTT fixed header + remaining length
- **CoAP**: CoAP version/type/code validation
- **RTSP**: RTSP method strings
- Confidence: 0.90-0.95

### 3. Medium-Confidence Heuristics (Port-Based)
- Encrypted ports: 443/tcp, 443/udp, 853/tcp, 8883/tcp, 5684/udp, 22/tcp
- Cleartext ports: 80/tcp, 53/udp, 1883/tcp, 5683/udp, 554/tcp
- Confidence: 0.60-0.85

### 4. Low-Confidence Entropy Analysis
- High entropy + low printable ratio → likely encrypted
- Confidence: 0.55-0.70
- **Note**: Currently not used in main detection flow

### 5. Unknown/Insufficient
- No evidence found
- Confidence: 0.5
- **API Mapping**: Unknown → `encrypted=False` (not_encrypted) but `state=unknown`, `evidence=insufficient`

## Output Format

### FlowResult

```python
@dataclass
class FlowResult:
    encrypted: bool              # Binary decision for API
    state: EncryptionState      # encrypted/cleartext/unknown
    encrypted_family: str        # tls/quic/dtls/unknown
    evidence: EvidenceType       # handshake/record_framing/dpi_proto/port_heuristic/entropy/insufficient
    confidence: float            # 0.0-1.0
    flow_id: str                # Flow identifier
    src_ip, src_port: str, int  # Source
    dst_ip, dst_port: str, int  # Destination
    protocol: str                # tcp/udp
    payload_bytes_captured: int  # Statistics
    packet_count: int
    first_seen, last_seen: float
    payload_sufficient: bool
```

### PacketResult

Similar structure for single packet analysis.

## Evidence Types

- **handshake**: TLS/DTLS handshake detected
- **record_framing**: TLS/DTLS/QUIC record framing detected
- **dpi_proto**: Cleartext protocol signature matched
- **port_heuristic**: Port-based heuristic used
- **entropy**: Entropy analysis suggested encryption
- **insufficient**: No sufficient evidence found

## Limitations

1. **Mid-stream captures**: May miss handshake packets, relies on record framing
2. **Truncated snaplen**: Falls back to heuristics when payload insufficient
3. **DoH indistinguishable**: DNS-over-HTTPS looks like normal HTTPS/TLS
4. **Protocol obfuscation**: Non-standard ports may be misclassified
5. **IPv6**: Currently only supports IPv4 (can be extended)
6. **Link types**: Assumes Ethernet (can be extended for other link types)

## Integration with MoE System

The encryption detector is called by the MoE router:

```python
from encryption_detector import analyze_pcap

results = analyze_pcap(pcap_path)
for result in results:
    if result.encrypted and result.confidence > 0.9:
        # Route to encrypted expert (TLS model)
        route_to_tls_expert(result)
    elif not result.encrypted and result.confidence > 0.9:
        # Route to selector gate for non-encrypted
        route_to_selector(result)
    else:
        # Unknown - router policy decides
        handle_unknown(result)
```

## Testing

```bash
# Run unit tests
python -m unittest encryption_detector.tests.test_signatures
python -m unittest encryption_detector.tests.test_detector_smoke

# Run all tests
python -m unittest discover encryption_detector/tests
```

## Module Structure

```
encryption_detector/
├── __init__.py          # Package exports
├── detector.py          # Main detection logic
├── pcap_reader.py       # PCAP parsing + flow reconstruction
├── signatures.py        # Protocol signature detection
├── utils.py             # Utility functions
├── cli.py               # Command-line interface
├── README.md            # This file
└── tests/
    ├── test_signatures.py
    └── test_detector_smoke.py
```

## Decision Rules Summary

| Priority | Method | Confidence | Evidence Type |
|----------|--------|------------|---------------|
| 1 | TLS/DTLS/QUIC framing | 0.90-0.98 | handshake/record_framing |
| 2 | Cleartext protocol signatures | 0.90-0.95 | dpi_proto |
| 3 | Port heuristics | 0.60-0.85 | port_heuristic |
| 4 | Entropy analysis | 0.55-0.70 | entropy |
| 5 | Unknown | 0.50 | insufficient |

## Confidence Semantics

- **0.95-0.99**: High confidence, strong evidence (framing, handshake, clear protocol signatures)
- **0.85-0.94**: High confidence, good evidence (port heuristics on well-known ports)
- **0.60-0.84**: Medium confidence, heuristic evidence (port-based, some uncertainty)
- **0.50-0.59**: Low confidence, weak evidence (entropy, insufficient data)
- **0.50**: Unknown, no evidence

## Notes

- **Unknown handling**: When `state=unknown`, the public API returns `encrypted=False` but keeps `evidence=insufficient` and low confidence. This allows the router to implement its own policy for unknown cases.
- **Truncation detection**: The module checks if payloads are sufficient for framing detection. If not, it falls back to heuristics.
- **Bidirectional flows**: Flow keys are normalized so both directions of a connection map to the same flow.

