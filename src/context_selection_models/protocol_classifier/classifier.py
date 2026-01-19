"""
Main protocol classifier API.

Provides deterministic protocol classification for cleartext traffic:
DNS, MQTT, CoAP, RTSP, OTHER, UNKNOWN
"""

from typing import List, Optional
from .types import (
    ProtocolLabel,
    EvidenceType,
    PacketClassification,
    FlowClassification,
    PacketMetadata
)
from .signatures import (
    detect_dns,
    detect_coap,
    detect_mqtt,
    detect_rtsp,
    get_port_hint
)
from .pcap_reader import read_pcap_simple, Flow, create_flow_key
from .reassembly import TCPReassembler


def classify_packet(packet_bytes: bytes, meta: PacketMetadata) -> PacketClassification:
    """
    Classify a single packet's protocol.
    
    Args:
        packet_bytes: Raw packet bytes (may include L2/L3 headers)
        meta: Packet metadata (L4 protocol, ports, IPs, payload offset)
    
    Returns:
        PacketClassification with label, confidence, evidence, notes
    """
    # Extract L4 payload
    if meta.captured_payload_offset > 0:
        if len(packet_bytes) < meta.captured_payload_offset:
            return PacketClassification(
                label=ProtocolLabel.UNKNOWN,
                confidence=0.0,
                evidence=EvidenceType.INSUFFICIENT,
                notes="packet_bytes too short for payload offset"
            )
        payload = packet_bytes[meta.captured_payload_offset:]
    else:
        # Assume packet_bytes is already L4 payload
        payload = packet_bytes
    
    if len(payload) == 0:
        return PacketClassification(
            label=ProtocolLabel.UNKNOWN,
            confidence=0.0,
            evidence=EvidenceType.INSUFFICIENT,
            notes="empty payload"
        )
    
    # Try protocol signatures based on L4 protocol
    if meta.l4_proto == "udp":
        # UDP: Try DNS and CoAP (both can be detected from single packet)
        
        # Try DNS first
        is_dns, dns_conf, dns_ev, dns_notes = detect_dns(payload)
        if is_dns:
            return PacketClassification(
                label=ProtocolLabel.DNS,
                confidence=dns_conf,
                evidence=dns_ev,
                notes=dns_notes
            )
        
        # Try CoAP
        is_coap, coap_conf, coap_ev, coap_notes = detect_coap(payload)
        if is_coap:
            return PacketClassification(
                label=ProtocolLabel.COAP,
                confidence=coap_conf,
                evidence=coap_ev,
                notes=coap_notes
            )
        
        # UDP but not DNS/CoAP -> OTHER
        return PacketClassification(
            label=ProtocolLabel.OTHER,
            confidence=0.6,
            evidence=EvidenceType.DPI_PARSE,
            notes="UDP payload does not match DNS or CoAP signatures"
        )
    
    elif meta.l4_proto == "tcp":
        # TCP: Try MQTT and RTSP (may need stream reassembly)
        
        # Try MQTT (packet-only, lower confidence)
        is_mqtt, mqtt_conf, mqtt_ev, mqtt_notes = detect_mqtt(payload, is_stream=False)
        if is_mqtt and mqtt_conf >= 0.75:
            return PacketClassification(
                label=ProtocolLabel.MQTT,
                confidence=mqtt_conf,
                evidence=mqtt_ev,
                notes=mqtt_notes
            )
        
        # Try RTSP (packet-only, lower confidence)
        is_rtsp, rtsp_conf, rtsp_ev, rtsp_notes = detect_rtsp(payload, is_stream=False)
        if is_rtsp and rtsp_conf >= 0.80:
            return PacketClassification(
                label=ProtocolLabel.RTSP,
                confidence=rtsp_conf,
                evidence=rtsp_ev,
                notes=rtsp_notes
            )
        
        # TCP packet without strong signature -> UNKNOWN (needs reassembly)
        if mqtt_ev == EvidenceType.NEEDS_TCP_REASSEMBLY or rtsp_ev == EvidenceType.NEEDS_TCP_REASSEMBLY:
            return PacketClassification(
                label=ProtocolLabel.UNKNOWN,
                confidence=0.5,
                evidence=EvidenceType.NEEDS_TCP_REASSEMBLY,
                notes="TCP packet requires stream reassembly for reliable classification"
            )
        
        # TCP but no clear signature -> UNKNOWN
        return PacketClassification(
            label=ProtocolLabel.UNKNOWN,
            confidence=0.5,
            evidence=EvidenceType.INSUFFICIENT,
            notes="TCP payload does not match MQTT or RTSP signatures"
        )
    
    else:
        # Unknown L4 protocol
        return PacketClassification(
            label=ProtocolLabel.UNKNOWN,
            confidence=0.0,
            evidence=EvidenceType.INSUFFICIENT,
            notes=f"unsupported L4 protocol: {meta.l4_proto}"
        )


def classify_flow(flow: Flow, reassembler: Optional[TCPReassembler] = None) -> FlowClassification:
    """
    Classify a flow's protocol.
    
    Args:
        flow: Flow object with packets
        reassembler: Optional TCP reassembler (for TCP flows)
    
    Returns:
        FlowClassification with label, confidence, evidence
    """
    if len(flow.packets) == 0:
        return FlowClassification(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
            label=ProtocolLabel.UNKNOWN,
            confidence=0.0,
            evidence=EvidenceType.INSUFFICIENT,
            packet_count=0,
            notes="empty flow"
        )
    
    # Collect statistics
    timestamps = [p.timestamp for p in flow.packets if hasattr(p, 'timestamp')]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None
    bytes_seen_up = sum(len(p.payload) for p in flow.packets if p.src_port < p.dst_port)
    bytes_seen_down = sum(len(p.payload) for p in flow.packets if p.src_port > p.dst_port)
    
    if flow.proto == "udp":
        # UDP: Check each datagram independently
        best_label = ProtocolLabel.UNKNOWN
        best_confidence = 0.0
        best_evidence = EvidenceType.INSUFFICIENT
        best_notes = None
        
        for packet in flow.packets:
            if len(packet.payload) == 0:
                continue
            
            # Try DNS
            is_dns, dns_conf, dns_ev, dns_notes = detect_dns(packet.payload)
            if is_dns and dns_conf > best_confidence:
                best_label = ProtocolLabel.DNS
                best_confidence = dns_conf
                best_evidence = dns_ev
                best_notes = dns_notes
            
            # Try CoAP
            is_coap, coap_conf, coap_ev, coap_notes = detect_coap(packet.payload)
            if is_coap and coap_conf > best_confidence:
                best_label = ProtocolLabel.COAP
                best_confidence = coap_conf
                best_evidence = coap_ev
                best_notes = coap_notes
        
        # If no signature found, check port hint
        if best_label == ProtocolLabel.UNKNOWN:
            port_hint_label, port_hint_conf = get_port_hint(flow.dst_port)
            if port_hint_label and port_hint_conf > 0:
                best_label = port_hint_label
                best_confidence = port_hint_conf
                best_evidence = EvidenceType.PORT_HINT
                best_notes = f"port-based hint: {flow.dst_port}"
        
        # If still unknown and has payload, mark as OTHER
        if best_label == ProtocolLabel.UNKNOWN and any(len(p.payload) > 0 for p in flow.packets):
            best_label = ProtocolLabel.OTHER
            best_confidence = 0.6
            best_evidence = EvidenceType.DPI_PARSE
            best_notes = "UDP flow with payload but no recognized protocol signature"
        
        return FlowClassification(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
            label=best_label,
            confidence=best_confidence,
            evidence=best_evidence,
            packet_count=len(flow.packets),
            first_seen=first_seen,
            last_seen=last_seen,
            bytes_seen_up=bytes_seen_up,
            bytes_seen_down=bytes_seen_down,
            notes=best_notes
        )
    
    elif flow.proto == "tcp":
        # TCP: Use stream reassembly if available
        stream_data = None
        is_stream = False
        
        if reassembler:
            # Reassemble TCP stream
            for packet in flow.packets:
                if packet.seq is not None:
                    direction = 0 if packet.src_port < packet.dst_port else 1
                    reassembler.add_packet(
                        flow.flow_id,
                        packet.seq,
                        packet.payload,
                        direction,
                        packet.timestamp
                    )
            
            stream_data = reassembler.get_stream(flow.flow_id)
            if stream_data and (len(stream_data.client_to_server) > 0 or len(stream_data.server_to_client) > 0):
                is_stream = True
        
        # Try to classify from reassembled stream or individual packets
        best_label = ProtocolLabel.UNKNOWN
        best_confidence = 0.0
        best_evidence = EvidenceType.INSUFFICIENT
        best_notes = None
        
        if is_stream and stream_data:
            # Try MQTT on reassembled stream
            combined_stream = stream_data.client_to_server + stream_data.server_to_client
            if len(combined_stream) > 0:
                is_mqtt, mqtt_conf, mqtt_ev, mqtt_notes = detect_mqtt(combined_stream, is_stream=True)
                if is_mqtt and mqtt_conf > best_confidence:
                    best_label = ProtocolLabel.MQTT
                    best_confidence = mqtt_conf
                    best_evidence = mqtt_ev
                    best_notes = mqtt_notes
                
                # Try RTSP on reassembled stream
                is_rtsp, rtsp_conf, rtsp_ev, rtsp_notes = detect_rtsp(combined_stream, is_stream=True)
                if is_rtsp and rtsp_conf > best_confidence:
                    best_label = ProtocolLabel.RTSP
                    best_confidence = rtsp_conf
                    best_evidence = rtsp_ev
                    best_notes = rtsp_notes
        
        # Fallback: Try individual packets
        if best_label == ProtocolLabel.UNKNOWN:
            for packet in flow.packets:
                if len(packet.payload) == 0:
                    continue
                
                # Try MQTT
                is_mqtt, mqtt_conf, mqtt_ev, mqtt_notes = detect_mqtt(packet.payload, is_stream=False)
                if is_mqtt and mqtt_conf > best_confidence:
                    best_label = ProtocolLabel.MQTT
                    best_confidence = mqtt_conf
                    best_evidence = mqtt_ev
                    best_notes = mqtt_notes
                
                # Try RTSP
                is_rtsp, rtsp_conf, rtsp_ev, rtsp_notes = detect_rtsp(packet.payload, is_stream=False)
                if is_rtsp and rtsp_conf > best_confidence:
                    best_label = ProtocolLabel.RTSP
                    best_confidence = rtsp_conf
                    best_evidence = rtsp_ev
                    best_notes = rtsp_notes
        
        # If no signature found, check port hint
        if best_label == ProtocolLabel.UNKNOWN:
            port_hint_label, port_hint_conf = get_port_hint(flow.dst_port)
            if port_hint_label and port_hint_conf > 0:
                best_label = port_hint_label
                best_confidence = port_hint_conf
                best_evidence = EvidenceType.PORT_HINT
                best_notes = f"port-based hint: {flow.dst_port}"
        
        # If still unknown and has payload, mark as OTHER or UNKNOWN
        if best_label == ProtocolLabel.UNKNOWN:
            if any(len(p.payload) > 0 for p in flow.packets):
                if best_evidence == EvidenceType.NEEDS_TCP_REASSEMBLY:
                    # Needs reassembly but couldn't do it
                    best_label = ProtocolLabel.UNKNOWN
                    best_confidence = 0.5
                    best_notes = "TCP flow requires stream reassembly for reliable classification"
                else:
                    best_label = ProtocolLabel.OTHER
                    best_confidence = 0.6
                    best_evidence = EvidenceType.DPI_PARSE
                    best_notes = "TCP flow with payload but no recognized protocol signature"
        
        return FlowClassification(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
            label=best_label,
            confidence=best_confidence,
            evidence=best_evidence,
            packet_count=len(flow.packets),
            first_seen=first_seen,
            last_seen=last_seen,
            bytes_seen_up=bytes_seen_up,
            bytes_seen_down=bytes_seen_down,
            notes=best_notes
        )
    
    else:
        # Unknown protocol
        return FlowClassification(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
            label=ProtocolLabel.UNKNOWN,
            confidence=0.0,
            evidence=EvidenceType.INSUFFICIENT,
            packet_count=len(flow.packets),
            first_seen=first_seen,
            last_seen=last_seen,
            bytes_seen_up=bytes_seen_up,
            bytes_seen_down=bytes_seen_down,
            notes=f"unsupported protocol: {flow.proto}"
        )


def classify_pcap(pcap_path: str, max_packets: Optional[int] = None) -> List[FlowClassification]:
    """
    Classify protocols in a PCAP file.
    
    Args:
        pcap_path: Path to PCAP file
        max_packets: Optional limit on packets to process
    
    Returns:
        List of FlowClassification objects (one per flow)
    """
    # Read PCAP and reconstruct flows
    flows = read_pcap_simple(pcap_path, max_packets=max_packets)
    
    # Create TCP reassembler for TCP flows
    reassembler = TCPReassembler()
    
    # Classify each flow
    results = []
    for flow in flows:
        result = classify_flow(flow, reassembler=reassembler if flow.proto == "tcp" else None)
        results.append(result)
    
    return results

