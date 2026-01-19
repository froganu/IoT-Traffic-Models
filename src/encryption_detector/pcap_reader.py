"""
PCAP file parsing and flow reconstruction.

Groups packets into flows using 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol).
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import struct


@dataclass
class Packet:
    """Represents a single network packet."""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # 'tcp' or 'udp'
    payload: bytes
    payload_length: int
    packet_length: int


@dataclass
class Flow:
    """Represents a network flow (group of packets with same 5-tuple)."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: List[Packet] = field(default_factory=list)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    total_bytes: int = 0
    payload_bytes_captured: int = 0
    
    def add_packet(self, packet: Packet):
        """Add a packet to this flow."""
        self.packets.append(packet)
        self.total_bytes += packet.packet_length
        self.payload_bytes_captured += packet.payload_length
        
        if self.first_seen is None or packet.timestamp < self.first_seen:
            self.first_seen = packet.timestamp
        if self.last_seen is None or packet.timestamp > self.last_seen:
            self.last_seen = packet.timestamp
    
    def is_payload_sufficient(self, min_payload_size: int = 5) -> bool:
        """
        Check if flow has sufficient payload for framing detection.
        
        Args:
            min_payload_size: Minimum payload size to consider sufficient
        
        Returns:
            True if flow has enough payload bytes
        """
        if len(self.packets) == 0:
            return False
        
        # Check if at least some packets have sufficient payload
        sufficient_count = sum(1 for p in self.packets if len(p.payload) >= min_payload_size)
        return sufficient_count >= 1  # At least one packet with sufficient payload


class PCAPReader:
    """
    Reads PCAP files and reconstructs flows.
    
    Supports basic PCAP format parsing. For production use, consider using
    scapy or pyshark for more robust parsing.
    """
    
    def __init__(self, pcap_path: str):
        """
        Initialize PCAP reader.
        
        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = pcap_path
        self.flows: Dict[str, Flow] = {}
    
    def read_flows(self, max_packets: Optional[int] = None) -> List[Flow]:
        """
        Read PCAP file and reconstruct flows.
        
        Args:
            max_packets: Optional limit on number of packets to read
        
        Returns:
            List of Flow objects
        """
        try:
            with open(self.pcap_path, 'rb') as f:
                # Read PCAP global header (24 bytes)
                global_header = f.read(24)
                if len(global_header) < 24:
                    raise ValueError("Invalid PCAP file: header too short")
                
                # Check magic number
                magic = struct.unpack('<I', global_header[0:4])[0]
                if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
                    # Try big-endian
                    magic = struct.unpack('>I', global_header[0:4])[0]
                    if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
                        raise ValueError("Invalid PCAP file: bad magic number")
                
                # Read packets
                packet_count = 0
                while True:
                    if max_packets and packet_count >= max_packets:
                        break
                    
                    # Read packet header (16 bytes)
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    # Parse packet header
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', packet_header)
                    timestamp = ts_sec + ts_usec / 1_000_000
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break
                    
                    # Parse packet
                    packet = self._parse_packet(timestamp, packet_data)
                    if packet:
                        self._add_packet_to_flow(packet)
                        packet_count += 1
                
        except Exception as e:
            raise ValueError(f"Error reading PCAP file: {e}")
        
        return list(self.flows.values())
    
    def _parse_packet(self, timestamp: float, packet_data: bytes) -> Optional[Packet]:
        """
        Parse a raw packet from PCAP data.
        
        Args:
            timestamp: Packet timestamp
            packet_data: Raw packet bytes
        
        Returns:
            Packet object or None if parsing fails
        """
        if len(packet_data) < 14:  # Minimum Ethernet header
            return None
        
        # Skip Ethernet header (14 bytes) - assume Ethernet
        # In production, handle different link types
        eth_header = packet_data[:14]
        eth_type = struct.unpack('>H', eth_header[12:14])[0]
        
        ip_data = packet_data[14:]
        
        # Parse IP header
        if len(ip_data) < 20:
            return None
        
        ip_version = (ip_data[0] >> 4) & 0x0F
        if ip_version != 4:  # Only support IPv4 for now
            return None
        
        ip_header_len = (ip_data[0] & 0x0F) * 4
        protocol = ip_data[9]
        src_ip = '.'.join(str(b) for b in ip_data[12:16])
        dst_ip = '.'.join(str(b) for b in ip_data[16:20])
        
        # Parse TCP or UDP
        l4_data = ip_data[ip_header_len:]
        if len(l4_data) < 8:
            return None
        
        if protocol == 6:  # TCP
            src_port = struct.unpack('>H', l4_data[0:2])[0]
            dst_port = struct.unpack('>H', l4_data[2:4])[0]
            tcp_header_len = ((l4_data[12] >> 4) & 0x0F) * 4
            payload = l4_data[tcp_header_len:]
            proto_str = 'tcp'
        elif protocol == 17:  # UDP
            src_port = struct.unpack('>H', l4_data[0:2])[0]
            dst_port = struct.unpack('>H', l4_data[2:4])[0]
            payload = l4_data[8:]
            proto_str = 'udp'
        else:
            return None  # Not TCP/UDP
        
        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto_str,
            payload=payload,
            payload_length=len(payload),
            packet_length=len(packet_data)
        )
    
    def _add_packet_to_flow(self, packet: Packet):
        """Add packet to appropriate flow based on 5-tuple."""
        # Create flow key (normalized for bidirectional flows)
        flow_key = self._create_flow_key(
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
            packet.protocol
        )
        
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(
                flow_id=flow_key,
                src_ip=packet.src_ip,
                src_port=packet.src_port,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                protocol=packet.protocol
            )
        
        self.flows[flow_key].add_packet(packet)
    
    @staticmethod
    def _create_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
        """Create normalized flow key."""
        # Normalize: use smaller port as first for bidirectional flows
        if src_port < dst_port or (src_port == dst_port and src_ip < dst_ip):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"


def read_pcap_simple(pcap_path: str, max_packets: Optional[int] = None) -> List[Flow]:
    """
    Simple function to read PCAP and return flows.
    
    Args:
        pcap_path: Path to PCAP file
        max_packets: Optional limit on packets
    
    Returns:
        List of Flow objects
    """
    reader = PCAPReader(pcap_path)
    return reader.read_flows(max_packets=max_packets)

