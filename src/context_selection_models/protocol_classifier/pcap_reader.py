"""
PCAP reader and flow reconstruction for protocol classification.

Parses PCAP files and reconstructs flows for protocol detection.
"""

from typing import List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import struct


@dataclass
class Packet:
    """Parsed packet with L4 information."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "tcp" or "udp"
    payload: bytes
    seq: Optional[int] = None  # TCP sequence number
    ack: Optional[int] = None   # TCP ACK number


@dataclass
class Flow:
    """Network flow (5-tuple)."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    packets: List[Packet]
    
    def get_payloads(self, direction: Optional[int] = None) -> List[bytes]:
        """
        Get payloads from flow packets.
        
        Args:
            direction: 0 = client->server, 1 = server->client, None = both
        
        Returns:
            List of payload bytes
        """
        if direction is None:
            return [p.payload for p in self.packets]
        
        # Determine direction based on port numbers (client typically has higher port)
        client_port = max(self.src_port, self.dst_port)
        
        payloads = []
        for p in self.packets:
            if direction == 0:  # client->server
                if p.src_port == client_port:
                    payloads.append(p.payload)
            else:  # server->client
                if p.dst_port == client_port:
                    payloads.append(p.payload)
        
        return payloads


def create_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> str:
    """
    Create a flow key from 5-tuple.
    
    Normalizes bidirectional flows by using smaller port first.
    """
    # Normalize: use smaller port as first for bidirectional flows
    if src_port < dst_port or (src_port == dst_port and src_ip < dst_ip):
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    else:
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"


def parse_ethernet_ip(packet_bytes: bytes) -> Optional[Tuple[str, str, str, bytes]]:
    """
    Parse Ethernet + IP headers to extract IP addresses and L4 payload.
    
    Args:
        packet_bytes: Raw packet bytes (starting from Ethernet header)
    
    Returns:
        Tuple of (src_ip, dst_ip, proto, l4_payload) or None if parse fails
    """
    if len(packet_bytes) < 14:  # Ethernet header
        return None
    
    # Skip Ethernet header (14 bytes)
    ip_start = 14
    
    # Check Ethernet type (0x0800 = IPv4)
    eth_type = struct.unpack('!H', packet_bytes[12:14])[0]
    if eth_type != 0x0800:
        return None  # Not IPv4
    
    if len(packet_bytes) < ip_start + 20:  # Minimum IP header
        return None
    
    # IP header
    ip_header = packet_bytes[ip_start:ip_start + 20]
    ip_version = (ip_header[0] >> 4) & 0x0F
    if ip_version != 4:
        return None  # Not IPv4
    
    ip_header_len = (ip_header[0] & 0x0F) * 4
    proto_byte = ip_header[9]
    
    # Extract IP addresses
    src_ip = f"{ip_header[12]}.{ip_header[13]}.{ip_header[14]}.{ip_header[15]}"
    dst_ip = f"{ip_header[16]}.{ip_header[17]}.{ip_header[18]}.{ip_header[19]}"
    
    # Map protocol
    if proto_byte == 6:
        proto = "tcp"
    elif proto_byte == 17:
        proto = "udp"
    else:
        return None  # Not TCP or UDP
    
    # Extract L4 payload
    l4_start = ip_start + ip_header_len
    if len(packet_bytes) < l4_start:
        return None
    
    l4_payload = packet_bytes[l4_start:]
    
    return src_ip, dst_ip, proto, l4_payload


def parse_tcp_header(l4_payload: bytes) -> Optional[Tuple[int, int, bytes]]:
    """
    Parse TCP header to extract ports, sequence, and payload.
    
    Args:
        l4_payload: TCP header + payload bytes
    
    Returns:
        Tuple of (src_port, dst_port, seq, ack, payload) or None if parse fails
    """
    if len(l4_payload) < 20:  # Minimum TCP header
        return None
    
    src_port = struct.unpack('!H', l4_payload[0:2])[0]
    dst_port = struct.unpack('!H', l4_payload[2:4])[0]
    seq = struct.unpack('!I', l4_payload[4:8])[0]
    ack = struct.unpack('!I', l4_payload[8:12])[0]
    
    data_offset = (l4_payload[12] >> 4) & 0x0F
    tcp_header_len = data_offset * 4
    
    if len(l4_payload) < tcp_header_len:
        return None
    
    payload = l4_payload[tcp_header_len:]
    
    return src_port, dst_port, seq, ack, payload


def parse_udp_header(l4_payload: bytes) -> Optional[Tuple[int, int, bytes]]:
    """
    Parse UDP header to extract ports and payload.
    
    Args:
        l4_payload: UDP header + payload bytes
    
    Returns:
        Tuple of (src_port, dst_port, payload) or None if parse fails
    """
    if len(l4_payload) < 8:  # UDP header
        return None
    
    src_port = struct.unpack('!H', l4_payload[0:2])[0]
    dst_port = struct.unpack('!H', l4_payload[2:4])[0]
    length = struct.unpack('!H', l4_payload[4:6])[0]
    
    if length < 8:
        return None
    
    payload = l4_payload[8:length] if len(l4_payload) >= length else l4_payload[8:]
    
    return src_port, dst_port, payload


def read_pcap_simple(pcap_path: str, max_packets: Optional[int] = None) -> List[Flow]:
    """
    Read PCAP file and reconstruct flows.
    
    This is a simplified PCAP reader. For production, consider using scapy or dpkt.
    
    Args:
        pcap_path: Path to PCAP file
        max_packets: Optional limit on packets to process
    
    Returns:
        List of Flow objects
    """
    flows: Dict[str, Flow] = {}
    
    try:
        # Try using scapy if available
        from scapy.all import rdpcap, IP, TCP, UDP
        
        packets = rdpcap(pcap_path)
        if max_packets:
            packets = packets[:max_packets]
        
        for pkt in packets:
            if IP not in pkt:
                continue
            
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            if TCP in pkt:
                proto = "tcp"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                payload = bytes(pkt[TCP].payload)
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
            elif UDP in pkt:
                proto = "udp"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                payload = bytes(pkt[UDP].payload)
                seq = None
                ack = None
            else:
                continue
            
            flow_key = create_flow_key(src_ip, src_port, dst_ip, dst_port, proto)
            
            if flow_key not in flows:
                flows[flow_key] = Flow(
                    flow_id=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    packets=[]
                )
            
            packet = Packet(
                timestamp=float(pkt.time),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                payload=payload,
                seq=seq,
                ack=ack
            )
            
            flows[flow_key].packets.append(packet)
    
    except ImportError:
        # Fallback: try dpkt
        try:
            import dpkt
            import socket
        except ImportError:
            raise ImportError(
                "Neither scapy nor dpkt is available. "
                "Install one: pip install scapy OR pip install dpkt"
            )
        
        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                packet_count = 0
                for ts, buf in pcap:
                    if max_packets and packet_count >= max_packets:
                        break
                    
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            proto = "tcp"
                            tcp = ip.data
                            src_port = tcp.sport
                            dst_port = tcp.dport
                            payload = bytes(tcp.data)
                            seq = tcp.seq
                            ack = tcp.ack
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            proto = "udp"
                            udp = ip.data
                            src_port = udp.sport
                            dst_port = udp.dport
                            payload = bytes(udp.data)
                            seq = None
                            ack = None
                        else:
                            continue
                        
                        flow_key = create_flow_key(src_ip, src_port, dst_ip, dst_port, proto)
                        
                        if flow_key not in flows:
                            flows[flow_key] = Flow(
                                flow_id=flow_key,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                proto=proto,
                                packets=[]
                            )
                        
                        packet = Packet(
                            timestamp=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            proto=proto,
                            payload=payload,
                            seq=seq,
                            ack=ack
                        )
                        
                        flows[flow_key].packets.append(packet)
                        packet_count += 1
                    
                    except (dpkt.dpkt.UnpackError, AttributeError, IndexError):
                        continue
        except Exception as e:
            raise RuntimeError(f"Error reading PCAP with dpkt: {e}")
    
    except Exception as e:
        raise RuntimeError(f"Error reading PCAP: {e}")
    
    return list(flows.values())

