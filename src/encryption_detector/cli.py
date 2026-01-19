"""
Command-line interface for encryption detector.
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import List

from .detector import analyze_pcap, analyze_packet, FlowResult, PacketResult


def export_csv(results: List[FlowResult], output_path: str):
    """
    Export results to CSV file.
    
    Args:
        results: List of FlowResult objects
        output_path: Output CSV file path
    """
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            'flow_id',
            'encrypted',
            'state',
            'encrypted_family',
            'evidence',
            'confidence',
            'src_ip',
            'src_port',
            'dst_ip',
            'dst_port',
            'protocol',
            'payload_bytes_captured',
            'packet_count',
            'first_seen',
            'last_seen',
            'payload_sufficient'
        ])
        
        # Write rows
        for result in results:
            writer.writerow([
                result.flow_id,
                result.encrypted,
                result.state.value,
                result.encrypted_family.value,
                result.evidence.value,
                result.confidence,
                result.src_ip,
                result.src_port,
                result.dst_ip,
                result.dst_port,
                result.protocol,
                result.payload_bytes_captured,
                result.packet_count,
                result.first_seen,
                result.last_seen,
                result.payload_sufficient
            ])


def export_json(results: List[FlowResult], output_path: str):
    """
    Export results to JSON file.
    
    Args:
        results: List of FlowResult objects
        output_path: Output JSON file path
    """
    data = []
    for result in results:
        data.append({
            'flow_id': result.flow_id,
            'encrypted': result.encrypted,
            'state': result.state.value,
            'encrypted_family': result.encrypted_family.value,
            'evidence': result.evidence.value,
            'confidence': result.confidence,
            'src_ip': result.src_ip,
            'src_port': result.src_port,
            'dst_ip': result.dst_ip,
            'dst_port': result.dst_port,
            'protocol': result.protocol,
            'payload_bytes_captured': result.payload_bytes_captured,
            'packet_count': result.packet_count,
            'first_seen': result.first_seen,
            'last_seen': result.last_seen,
            'payload_sufficient': result.payload_sufficient
        })
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Encryption Detector for MoE IoT C2 Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--pcap',
        type=str,
        help='Path to PCAP file to analyze'
    )
    
    parser.add_argument(
        '--packet',
        type=str,
        help='Path to raw packet file (bytes) to analyze'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        help='Port number (for single packet analysis)'
    )
    
    parser.add_argument(
        '--protocol',
        type=str,
        choices=['tcp', 'udp'],
        help='Protocol (for single packet analysis)'
    )
    
    parser.add_argument(
        '--out',
        type=str,
        help='Output file path (CSV or JSON based on extension)'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['csv', 'json'],
        default='csv',
        help='Output format (default: csv)'
    )
    
    parser.add_argument(
        '--max-packets',
        type=int,
        help='Maximum number of packets to process from PCAP'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.pcap and not args.packet:
        parser.error("Must specify either --pcap or --packet")
    
    if args.pcap and args.packet:
        parser.error("Cannot specify both --pcap and --packet")
    
    try:
        if args.pcap:
            # Analyze PCAP file
            print(f"Analyzing PCAP file: {args.pcap}")
            results = analyze_pcap(args.pcap, max_packets=args.max_packets)
            print(f"Found {len(results)} flows")
            
            if args.out:
                output_path = Path(args.out)
                if output_path.suffix == '.json' or args.format == 'json':
                    export_json(results, args.out)
                else:
                    export_csv(results, args.out)
                print(f"Results exported to: {args.out}")
            else:
                # Print summary
                print("\nResults:")
                print("-" * 80)
                for result in results:
                    print(f"Flow {result.flow_id}: {result.state.value} "
                          f"({result.encrypted_family.value}) - "
                          f"confidence={result.confidence:.2f}, "
                          f"evidence={result.evidence.value}")
        
        elif args.packet:
            # Analyze single packet
            print(f"Analyzing packet file: {args.packet}")
            with open(args.packet, 'rb') as f:
                packet_bytes = f.read()
            
            result = analyze_packet(
                packet_bytes,
                port=args.port,
                protocol=args.protocol
            )
            
            print(f"\nResult:")
            print(f"  Encrypted: {result.encrypted}")
            print(f"  State: {result.state.value}")
            print(f"  Family: {result.encrypted_family.value}")
            print(f"  Evidence: {result.evidence.value}")
            print(f"  Confidence: {result.confidence:.2f}")
            
            if args.out:
                # Export single result
                if Path(args.out).suffix == '.json' or args.format == 'json':
                    with open(args.out, 'w') as f:
                        json.dump({
                            'encrypted': result.encrypted,
                            'state': result.state.value,
                            'encrypted_family': result.encrypted_family.value,
                            'evidence': result.evidence.value,
                            'confidence': result.confidence,
                            'port': result.port,
                            'protocol': result.protocol
                        }, f, indent=2)
                else:
                    # CSV for single packet
                    with open(args.out, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['encrypted', 'state', 'encrypted_family', 'evidence', 'confidence', 'port', 'protocol'])
                        writer.writerow([
                            result.encrypted,
                            result.state.value,
                            result.encrypted_family.value,
                            result.evidence.value,
                            result.confidence,
                            result.port,
                            result.protocol
                        ])
                print(f"\nResults exported to: {args.out}")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

