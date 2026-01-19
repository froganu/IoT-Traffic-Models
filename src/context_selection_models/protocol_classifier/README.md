# Protocol Classifier

Deterministic protocol classifier for cleartext network traffic. Used in Phase 2 (Context Selection) of the MoE pipeline to distinguish between DNS, MQTT, CoAP, and RTSP protocols.

## Overview

The Protocol Classifier provides **deterministic** (no ML/AI) protocol detection for cleartext traffic. It uses Deep Packet Inspection (DPI) signatures to identify protocols based on their header structures and message formats.

### Supported Protocols

- **DNS** (UDP/TCP) - Domain Name System
- **MQTT** (TCP) - Message Queuing Telemetry Transport
- **CoAP v1** (UDP) - Constrained Application Protocol
- **RTSP** (TCP) - Real-Time Streaming Protocol
- **OTHER** - Cleartext but not one of the above
- **UNKNOWN** - Insufficient evidence for classification

## Architecture

```
protocol_classifier/
├── classifier.py      # Main API (classify_packet, classify_pcap)
├── signatures.py       # Protocol signature detection (DPI)
├── pcap_reader.py      # PCAP parsing and flow reconstruction
├── reassembly.py       # TCP stream reassembly for MQTT/RTSP
├── types.py            # Data classes and enums
├── cli.py              # Command-line interface
└── tests/              # Unit tests
```

## Usage

### Single Packet Classification

```python
from src.context_selection_models import classify_packet, PacketMetadata, ProtocolLabel

# Create packet metadata
meta = PacketMetadata(
    l4_proto="udp",
    src_port=54321,
    dst_port=53,
    captured_payload_offset=0
)

# Classify
packet_bytes = b'\x12\x34\x01\x00\x00\x01...'  # DNS query payload
result = classify_packet(packet_bytes, meta)

print(f"Label: {result.label.value}")
print(f"Confidence: {result.confidence:.2f}")
print(f"Evidence: {result.evidence.value}")
```

### PCAP File Classification

```python
from src.context_selection_models import classify_pcap

# Classify all flows in a PCAP
results = classify_pcap("traffic.pcap")

for flow in results:
    print(f"Flow {flow.flow_id}: {flow.label.value} ({flow.confidence:.2f})")
```

### Command-Line Interface

```bash
# Classify PCAP and export to CSV
python -m src.context_selection_models.protocol_classifier.cli --pcap traffic.pcap --out results.csv

# Export as JSON
python -m src.context_selection_models.protocol_classifier.cli --pcap traffic.pcap --out results.json --format json

# Limit packet processing
python -m src.context_selection_models.protocol_classifier.cli --pcap traffic.pcap --out results.csv --max-packets 10000
```

## Classification Rules

### 1. DNS Detection (UDP/TCP)

**Signature**: DNS header structure (12 bytes minimum)
- Validates Transaction ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
- Checks opcode validity (0-5)
- Optionally parses QNAME structure

**Confidence**: 0.95 (high)
**Evidence**: `dns_header`

**Single Packet**: ✅ Yes (UDP datagrams are self-contained)

### 2. CoAP v1 Detection (UDP)

**Signature**: CoAP header structure (4 bytes minimum)
- Version = 1 (bits 6-7)
- Type = 0-3 (bits 4-5)
- Token Length = 0-8 (bits 0-3)
- Code validation (0.xx, 2.xx, 4.xx, 5.xx)

**Confidence**: 0.85-0.95
**Evidence**: `coap_header`

**Single Packet**: ✅ Yes (UDP datagrams are self-contained)

### 3. MQTT Detection (TCP)

**Signature**: MQTT fixed header + variable-length remaining length
- Packet type: 1-14 (0 and 15 are reserved)
- Remaining length: Variable-length encoding (1-4 bytes)
- Optional: CONNECT packet validation (protocol name "MQTT")

**Confidence**: 
- Stream-based: 0.95
- Packet-only: 0.75-0.85

**Evidence**: `mqtt_fixed_header` or `mqtt_connect_packet`

**Single Packet**: ⚠️ Limited (often needs TCP reassembly)

### 4. RTSP Detection (TCP)

**Signature**: RTSP request/response lines
- Request methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, etc.
- Response: "RTSP/1.0" or "RTSP/1.1"
- URI patterns: "rtsp://" or "*"

**Confidence**:
- Stream-based: 0.95
- Packet-only: 0.80-0.85

**Evidence**: `rtsp_request_line` or `rtsp_response_line`

**Single Packet**: ⚠️ Limited (often needs TCP reassembly)

## Why TCP Reassembly?

MQTT and RTSP are TCP-based protocols that may span multiple packets:

1. **Message Fragmentation**: A single MQTT CONNECT or RTSP request may be split across multiple TCP segments
2. **Header Parsing**: MQTT's variable-length "remaining length" field requires reading multiple bytes, which may span packets
3. **Request/Response Lines**: RTSP request lines are ASCII text that may be split across packets

**Solution**: The classifier uses TCP stream reassembly to reconstruct complete messages before classification.

### When Reassembly is Needed

- **Single Packet Mode**: Returns `UNKNOWN` with `evidence=needs_tcp_reassembly` if signature is incomplete
- **PCAP Mode**: Automatically performs TCP reassembly for TCP flows

## Evidence and Confidence

### Evidence Types

- `dns_header` - DNS header structure detected
- `coap_header` - CoAP header structure detected
- `mqtt_fixed_header` - MQTT fixed header detected
- `mqtt_connect_packet` - MQTT CONNECT packet validated
- `rtsp_request_line` - RTSP request line detected
- `rtsp_response_line` - RTSP response line detected
- `dpi_parse` - DPI parsing completed but no signature matched
- `port_hint` - Port-based hint (low confidence)
- `insufficient` - Insufficient payload for classification
- `needs_tcp_reassembly` - TCP reassembly required

### Confidence Levels

- **0.90-0.95**: High confidence (strong signature match)
- **0.75-0.89**: Medium confidence (partial signature or packet-only detection)
- **0.60-0.74**: Low confidence (port hints or weak signatures)
- **0.00-0.59**: Very low confidence (insufficient evidence)

## Limitations

1. **Truncated PCAPs**: If payload is truncated (snaplen too small), classification may return `UNKNOWN`
2. **Mid-Stream Capture**: TCP flows captured mid-stream may not have complete messages
3. **Encrypted Traffic**: This classifier is for **cleartext only**. Encrypted traffic should be handled by Phase 1 (encryption detector)
4. **Port-Based Hints**: Port numbers are only used as weak hints when signatures are insufficient
5. **Protocol Versions**: 
   - CoAP: Only v1 is supported
   - MQTT: Supports MQTT 3.1.1 and 5.0
   - RTSP: Supports RTSP/1.0 and RTSP/1.1

## Dependencies

- **Python 3.11+**
- **scapy** OR **dpkt** (for PCAP parsing)
  ```bash
  pip install scapy
  # OR
  pip install dpkt
  ```

## Testing

Run individual protocol tests:

```bash
python3 src/context_selection_models/protocol_classifier/tests/test_dns.py
python3 src/protocol_classifier/tests/test_coap.py
python3 src/protocol_classifier/tests/test_mqtt.py
python3 src/protocol_classifier/tests/test_rtsp.py
python3 src/protocol_classifier/tests/test_pcap_flow.py
```

## Integration with MoE Pipeline

The Protocol Classifier is used in Phase 2 (Context Selection) of the MoE pipeline:

```python
from src.moe.integration import select_ai_model
from src.context_selection_models import classify_packet, PacketMetadata

# After Phase 1 determines traffic is cleartext
meta = PacketMetadata(l4_proto="udp", dst_port=53, ...)
result = classify_packet(packet_bytes, meta)

# Route based on protocol
if result.label == ProtocolLabel.DNS:
    model = "dns_model"
elif result.label == ProtocolLabel.MQTT:
    model = "mqtt_model"
# ... etc
```

## Performance

- **Single Packet**: < 1ms per packet
- **PCAP Processing**: ~1000-10000 packets/second (depends on PCAP size and complexity)
- **TCP Reassembly**: Adds ~10-20% overhead for TCP flows

## Future Enhancements

- Support for additional protocols (HTTP, Modbus, etc.)
- Enhanced TCP reassembly (handle out-of-order packets, retransmissions)
- Protocol version detection (MQTT 3.1.1 vs 5.0, CoAP v1 vs v2)
- Performance optimizations for large PCAPs

