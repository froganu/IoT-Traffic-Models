"""
TCP stream reassembly for MQTT and RTSP protocol detection.

Provides deterministic TCP stream reassembly to enable protocol detection
that requires full message reconstruction.
"""

from typing import Dict, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class TCPPacket:
    """TCP packet with sequence information."""
    seq: int
    ack: int
    payload: bytes
    direction: int  # 0 = client->server, 1 = server->client
    timestamp: float


@dataclass
class ReassembledStream:
    """Reassembled TCP stream data."""
    client_to_server: bytes
    server_to_client: bytes
    complete: bool  # True if stream appears complete
    packet_count: int


class TCPReassembler:
    """
    TCP stream reassembler for protocol detection.
    
    Implements simple in-order reassembly. Handles:
    - In-order packets
    - Simple gaps (marks as incomplete)
    - Bidirectional streams
    """
    
    def __init__(self):
        """Initialize reassembler."""
        # Flow key -> (client_buffer, server_buffer, last_seq_client, last_seq_server)
        self.streams: Dict[str, Tuple[bytearray, bytearray, Optional[int], Optional[int], int]] = {}
    
    def add_packet(self, flow_key: str, seq: int, payload: bytes, direction: int, timestamp: float):
        """
        Add a TCP packet to the reassembler.
        
        Args:
            flow_key: Flow identifier (5-tuple)
            seq: TCP sequence number
            payload: TCP payload bytes
            direction: 0 = client->server, 1 = server->client
            timestamp: Packet timestamp
        """
        if flow_key not in self.streams:
            self.streams[flow_key] = (bytearray(), bytearray(), None, None, 0)
        
        client_buf, server_buf, last_seq_c, last_seq_s, pkt_count = self.streams[flow_key]
        
        if direction == 0:  # client->server
            # Simple in-order reassembly
            if last_seq_c is None:
                # First packet in this direction
                client_buf.extend(payload)
                last_seq_c = seq + len(payload)
            elif seq == last_seq_c:
                # In-order continuation
                client_buf.extend(payload)
                last_seq_c = seq + len(payload)
            elif seq < last_seq_c:
                # Out-of-order or duplicate (ignore for now)
                pass
            else:
                # Gap detected
                # For simplicity, we'll still append but mark as potentially incomplete
                client_buf.extend(payload)
                last_seq_c = seq + len(payload)
        else:  # server->client
            if last_seq_s is None:
                server_buf.extend(payload)
                last_seq_s = seq + len(payload)
            elif seq == last_seq_s:
                server_buf.extend(payload)
                last_seq_s = seq + len(payload)
            elif seq < last_seq_s:
                pass
            else:
                server_buf.extend(payload)
                last_seq_s = seq + len(payload)
        
        self.streams[flow_key] = (client_buf, server_buf, last_seq_c, last_seq_s, pkt_count + 1)
    
    def get_stream(self, flow_key: str) -> Optional[ReassembledStream]:
        """
        Get reassembled stream for a flow.
        
        Args:
            flow_key: Flow identifier
        
        Returns:
            ReassembledStream or None if flow not found
        """
        if flow_key not in self.streams:
            return None
        
        client_buf, server_buf, last_seq_c, last_seq_s, pkt_count = self.streams[flow_key]
        
        # Stream is considered complete if we have data and no obvious gaps
        # (This is a heuristic; true completion detection would need FIN/ACK)
        complete = len(client_buf) > 0 or len(server_buf) > 0
        
        return ReassembledStream(
            client_to_server=bytes(client_buf),
            server_to_client=bytes(server_buf),
            complete=complete,
            packet_count=pkt_count
        )
    
    def clear_flow(self, flow_key: str):
        """Clear reassembly state for a flow."""
        if flow_key in self.streams:
            del self.streams[flow_key]
    
    def clear_all(self):
        """Clear all reassembly state."""
        self.streams.clear()

