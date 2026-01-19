#!/usr/bin/env python3
"""
Command-line interface for protocol classifier.

Usage:
    python -m src.context_selection_models.protocol_classifier.cli --pcap file.pcap --out results.csv
    python -m protocol_classifier.cli --pcap file.pcap --format json
"""

import argparse
import sys
import csv
import json
from pathlib import Path
from typing import List

from .classifier import classify_pcap
from .types import FlowClassification


def export_csv(results: List[FlowClassification], output_path: str):
    """Export classification results to CSV."""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'flow_id',
            'src_ip', 'src_port',
            'dst_ip', 'dst_port',
            'proto',
            'label',
            'confidence',
            'evidence',
            'packet_count',
            'bytes_up', 'bytes_down',
            'first_seen', 'last_seen',
            'notes'
        ])
        
        for result in results:
            writer.writerow([
                result.flow_id,
                result.src_ip, result.src_port,
                result.dst_ip, result.dst_port,
                result.proto,
                result.label.value,
                result.confidence,
                result.evidence.value,
                result.packet_count,
                result.bytes_seen_up, result.bytes_seen_down,
                result.first_seen, result.last_seen,
                result.notes or ''
            ])


def export_json(results: List[FlowClassification], output_path: str):
    """Export classification results to JSON."""
    data = []
    for result in results:
        data.append({
            'flow_id': result.flow_id,
            'src_ip': result.src_ip,
            'src_port': result.src_port,
            'dst_ip': result.dst_ip,
            'dst_port': result.dst_port,
            'proto': result.proto,
            'label': result.label.value,
            'confidence': result.confidence,
            'evidence': result.evidence.value,
            'packet_count': result.packet_count,
            'bytes_seen_up': result.bytes_seen_up,
            'bytes_seen_down': result.bytes_seen_down,
            'first_seen': result.first_seen,
            'last_seen': result.last_seen,
            'notes': result.notes
        })
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Protocol Classifier for Cleartext Traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Classify PCAP and export to CSV
  python -m protocol_classifier.cli --pcap traffic.pcap --out results.csv
  
  # Export as JSON
  python -m protocol_classifier.cli --pcap traffic.pcap --out results.json --format json
  
  # Limit packet processing
  python -m protocol_classifier.cli --pcap traffic.pcap --out results.csv --max-packets 10000
        """
    )
    
    parser.add_argument(
        '--pcap',
        type=str,
        required=True,
        help='Path to PCAP file'
    )
    
    parser.add_argument(
        '--out',
        type=str,
        required=True,
        help='Output file path (CSV or JSON)'
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
        default=None,
        help='Maximum packets to process (default: all)'
    )
    
    args = parser.parse_args()
    
    # Validate input
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"Error: PCAP file not found: {pcap_path}", file=sys.stderr)
        return 1
    
    # Classify
    print(f"Reading PCAP: {pcap_path}")
    print(f"Processing up to {args.max_packets or 'all'} packets...")
    
    try:
        results = classify_pcap(str(pcap_path), max_packets=args.max_packets)
        print(f"Classified {len(results)} flows")
    except Exception as e:
        print(f"Error classifying PCAP: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    
    # Export
    output_path = Path(args.out)
    print(f"Exporting results to: {output_path}")
    
    try:
        if args.format == 'json' or output_path.suffix == '.json':
            export_json(results, str(output_path))
        else:
            export_csv(results, str(output_path))
        print("✓ Export complete")
    except Exception as e:
        print(f"Error exporting results: {e}", file=sys.stderr)
        return 1
    
    # Print summary
    print("\n" + "=" * 60)
    print("CLASSIFICATION SUMMARY")
    print("=" * 60)
    label_counts = {}
    for result in results:
        label = result.label.value
        label_counts[label] = label_counts.get(label, 0) + 1
    
    for label, count in sorted(label_counts.items()):
        print(f"  {label:10s}: {count:4d} flows")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

