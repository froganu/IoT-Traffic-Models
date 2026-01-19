"""
Test TLS Record Extraction with Real Data

Tests the TLS record extraction implementation using data from the training repository.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import json

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.moe.tls_record_extractor import (
    extract_tls_features_from_packet_sequence,
    extract_tls_features_from_records,
    TLSRecord,
    _parse_tls_records_from_bytes,
    _reassemble_tcp_stream,
)

# Path to training repository
TRAINING_REPO = Path("/Users/hasanagbaria/UPC/TMA/project/models/extending12to13")


def load_joy_json(joy_file: Path):
    """Load Joy JSON file."""
    with open(joy_file, 'r') as f:
        data = json.load(f)
        # Joy JSON can be a list of flows or a single flow
        if isinstance(data, list):
            # Return first flow for testing
            return data[0] if len(data) > 0 else {}
        return data


def extract_tls_records_from_joy(joy_data: dict) -> list:
    """
    Extract TLS records from Joy JSON data.
    
    Joy format: j['tls']['srlt'] = list of TLS records
    Each record has: 'b' (record size), 'dir' (direction), 'tp' (type), 'ipt' (inter-packet time)
    """
    tls_records = []
    
    if 'tls' in joy_data and 'srlt' in joy_data['tls']:
        for record_data in joy_data['tls']['srlt']:
            # Joy's 'b' is record size (payload, excluding header)
            # Joy's 'dir' is direction (0=client→server, 1=server→client)
            record = TLSRecord(
                size=record_data.get('b', 0),
                direction=record_data.get('dir', 0),
                record_type=None
            )
            tls_records.append(record)
    
    return tls_records


def create_packet_dataframe_from_joy(joy_data: dict) -> pd.DataFrame:
    """
    Create a packet DataFrame from Joy JSON data.
    
    This is a simplified conversion - in practice, you'd need to reconstruct
    packets from the flow data or use the original PCAP.
    """
    # Extract flow information
    src_ip = joy_data.get('sa', '0.0.0.0')
    dst_ip = joy_data.get('da', '0.0.0.0')
    src_port = joy_data.get('sp', 0)
    dst_port = joy_data.get('dp', 0)
    protocol = 'tcp'  # TLS is over TCP
    
    # Try to reconstruct TCP payload from TLS records
    # This is simplified - real implementation would need full packet reconstruction
    tcp_payload = b''
    
    if 'tls' in joy_data and 'srlt' in joy_data['tls']:
        for record in joy_data['tls']['srlt']:
            # Reconstruct TLS record header + payload
            # Content type (1 byte) + version (2 bytes) + length (2 bytes) + payload
            record_size = record.get('b', 0)
            content_type = 0x17  # ApplicationData (default)
            version = 0x0303  # TLS 1.2 (default)
            
            # Create TLS record header
            record_header = bytes([
                content_type,
                (version >> 8) & 0xFF,
                version & 0xFF,
                (record_size >> 8) & 0xFF,
                record_size & 0xFF
            ])
            
            # Add dummy payload (we don't have the actual payload, just size)
            record_payload = b'X' * record_size
            
            tcp_payload += record_header + record_payload
    
    # Create packet DataFrame
    # Note: This is a simplified representation
    # Real packets would have full Ethernet/IP/TCP headers
    packet_data = {
        'src_ip': [src_ip],
        'dst_ip': [dst_ip],
        'src_port': [src_port],
        'dst_port': [dst_port],
        'protocol': [protocol],
        'direction': [0 if dst_port == 443 else 1],  # Simplified direction
        'packet_bytes': [tcp_payload] if tcp_payload else [b''],
    }
    
    return pd.DataFrame(packet_data)


def test_with_joy_json(joy_file: Path):
    """Test TLS record extraction with a Joy JSON file."""
    print(f"\n{'='*70}")
    print(f"Testing with: {joy_file.name}")
    print(f"{'='*70}")
    
    try:
        # Load Joy JSON
        joy_data = load_joy_json(joy_file)
        
        # Skip if not a dict (might be a list or other format)
        if not isinstance(joy_data, dict):
            print(f"   ⚠️  Skipping: JSON is not a dict (type: {type(joy_data)})")
            return None, None
        
        # Extract TLS records from Joy (ground truth)
        joy_records = extract_tls_records_from_joy(joy_data)
        print(f"\n📊 Joy Data:")
        print(f"   - Source IP: {joy_data.get('sa', 'N/A')}")
        print(f"   - Dest IP: {joy_data.get('da', 'N/A')}")
        print(f"   - Source Port: {joy_data.get('sp', 'N/A')}")
        print(f"   - Dest Port: {joy_data.get('dp', 'N/A')}")
        print(f"   - TLS Records (from Joy): {len(joy_records)}")
        
        if joy_records:
            print(f"   - First 3 records:")
            for i, r in enumerate(joy_records[:3]):
                print(f"     Record {i+1}: size={r.size}, direction={r.direction}")
        
        # Extract features from Joy records (ground truth)
        joy_features = extract_tls_features_from_records(joy_records)
        print(f"\n✅ Joy Features (ground truth):")
        print(f"   - Shape: {joy_features.shape}")
        print(f"   - First 10 (tls_b_0-9): {joy_features[0][:10]}")
        print(f"   - Next 10 (tls_dir_0-9): {joy_features[0][10:20]}")
        
        # Create packet DataFrame (simplified)
        packet_df = create_packet_dataframe_from_joy(joy_data)
        
        # Extract features using our implementation
        print(f"\n🔧 Our Implementation:")
        our_features = extract_tls_features_from_packet_sequence([packet_df])
        print(f"   - Shape: {our_features.shape}")
        print(f"   - First 10 (tls_b_0-9): {our_features[0][:10]}")
        print(f"   - Next 10 (tls_dir_0-9): {our_features[0][10:20]}")
        
        # Compare
        print(f"\n📈 Comparison:")
        if len(joy_records) > 0:
            # Compare first record
            if len(joy_records) > 0:
                joy_first = joy_records[0]
                print(f"   - Joy first record: size={joy_first.size}, dir={joy_first.direction}")
            
            # Check if our features match (at least in structure)
            if not np.all(our_features == -1):
                print(f"   - ✅ Our implementation extracted features")
                # Check if first feature matches
                if our_features[0][0] != -1:
                    print(f"   - First feature (tls_b_0): {our_features[0][0]}")
                    if len(joy_records) > 0:
                        print(f"   - Joy first record size: {joy_records[0].size}")
                        if abs(our_features[0][0] - joy_records[0].size) < 1:
                            print(f"   - ✅ Size matches!")
                        else:
                            print(f"   - ⚠️  Size mismatch (expected: {joy_records[0].size}, got: {our_features[0][0]})")
            else:
                print(f"   - ⚠️  Our implementation returned all -1 (no records extracted)")
        else:
            print(f"   - ⚠️  No TLS records in Joy data")
        
        return joy_features, our_features
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def main():
    """Main test function."""
    print("="*70)
    print("TLS RECORD EXTRACTION TEST")
    print("="*70)
    
    # Find Joy JSON files in training repository (exclude config files)
    all_json_files = list(TRAINING_REPO.rglob("*.json"))
    joy_files = [f for f in all_json_files 
                 if 'datasets' in f.name or 'joy' in f.name.lower()]
    
    # Also check for CSV files with TLS features
    csv_files = list(TRAINING_REPO.rglob("*tls*behav*.csv"))
    csv_files.extend(list(TRAINING_REPO.rglob("*tls13*.csv")))
    
    if not joy_files and not csv_files:
        print(f"\n⚠️  No JSON files found in {TRAINING_REPO}")
        print("   Looking for processed data or CSV files...")
        
        # Try to find CSV files with TLS features
        csv_files = list(TRAINING_REPO.rglob("*.csv"))
        if csv_files:
            print(f"   Found {len(csv_files)} CSV files")
            # Try to load one and check if it has TLS features
            for csv_file in csv_files[:3]:
                try:
                    df = pd.read_csv(csv_file, nrows=5)
                    if 'tls_b_0' in df.columns or 'tls_dir_0' in df.columns:
                        print(f"\n   ✅ Found CSV with TLS features: {csv_file.name}")
                        print(f"   Columns: {list(df.columns)[:10]}...")
                        return test_with_csv(csv_file)
                except Exception as e:
                    continue
        
        print("\n   Creating synthetic test instead...")
        return test_synthetic()
    
    print(f"\n📁 Found {len(joy_files)} Joy JSON files")
    print(f"📁 Found {len(csv_files)} CSV files with TLS features")
    
    # Test with CSV files first (easier to validate)
    if csv_files:
        print(f"\n{'='*70}")
        print("TESTING WITH CSV FILES (Processed TLS Features)")
        print(f"{'='*70}")
        for csv_file in csv_files[:3]:  # Test first 3 CSV files
            test_with_csv(csv_file)
    
    # Test with Joy JSON files
    results = []
    if joy_files:
        print(f"\n{'='*70}")
        print("TESTING WITH JOY JSON FILES")
        print(f"{'='*70}")
        for joy_file in joy_files[:3]:  # Test first 3 files
            joy_feat, our_feat = test_with_joy_json(joy_file)
            if joy_feat is not None and our_feat is not None:
                results.append((joy_file.name, joy_feat, our_feat))
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Tested {len(results)} files")
    
    if results:
        print("\n✅ Tests completed!")
    else:
        print("\n⚠️  No successful tests")


def test_with_csv(csv_file: Path):
    """Test with CSV file containing TLS features."""
    print(f"\n{'='*70}")
    print(f"Testing with CSV: {csv_file.name}")
    print(f"{'='*70}")
    
    try:
        # Load CSV
        df = pd.read_csv(csv_file, nrows=5)
        
        print(f"\n📊 CSV Data:")
        print(f"   - Rows: {len(df)}")
        print(f"   - Total columns: {len(df.columns)}")
        
        # Check for TLS features
        tls_b_cols = sorted([col for col in df.columns if col.startswith('tls_b_')])
        tls_dir_cols = sorted([col for col in df.columns if col.startswith('tls_dir_')])
        
        if tls_b_cols or tls_dir_cols:
            print(f"   - Found TLS features: {len(tls_b_cols)} tls_b, {len(tls_dir_cols)} tls_dir")
            
            # Get first row's TLS features (ground truth from training data)
            if tls_b_cols and tls_dir_cols:
                first_row = df.iloc[0]
                tls_b_values = [first_row[col] for col in tls_b_cols[:10]]
                tls_dir_values = [first_row[col] for col in tls_dir_cols[:10]]
                
                print(f"\n   ✅ Ground Truth (from training data):")
                print(f"   - tls_b_0-9: {tls_b_values}")
                print(f"   - tls_dir_0-9: {tls_dir_values}")
                
                # Create feature array for comparison
                ground_truth = np.array(tls_b_values + tls_dir_values, dtype=np.float64).reshape(1, 20)
                print(f"   - Feature array shape: {ground_truth.shape}")
                print(f"   - Non-missing features: {np.sum(ground_truth[0] != -1)}/20")
        
        print("\n   ℹ️  Note: CSV contains processed features, not raw packets.")
        print("   To test extraction, we need:")
        print("   1. Original PCAP files, OR")
        print("   2. Joy JSON files with raw TLS record data")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


def test_synthetic():
    """Test with synthetic TLS data."""
    print(f"\n{'='*70}")
    print("Synthetic Test")
    print(f"{'='*70}")
    
    # Create synthetic TLS records
    tls_record1 = bytes([0x17, 0x03, 0x03, 0x00, 0x64]) + b'A' * 100  # 100 bytes
    tls_record2 = bytes([0x17, 0x03, 0x03, 0x00, 0x32]) + b'B' * 50   # 50 bytes
    
    # Create packet with TLS records
    import struct
    def create_tcp_packet(src_ip, dst_ip, src_port, dst_port, tcp_payload):
        eth_header = b'\x00' * 14
        ip_version_ihl = 0x45
        ip_total_len = 20 + 20 + len(tcp_payload)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_version_ihl, 0x00, ip_total_len, 0x1234, 0x4000,
            64, 6, 0x0000,
            struct.pack('!4B', *map(int, src_ip.split('.'))),
            struct.pack('!4B', *map(int, dst_ip.split('.')))
        )
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port, dst_port, 0x12345678, 0x00000000,
            (5 << 4), 0x18, 0x2000, 0x0000, 0x0000
        )
        return eth_header + ip_header + tcp_header + tcp_payload
    
    packet1_bytes = create_tcp_packet('192.168.1.100', '192.168.1.1', 54321, 443, tls_record1)
    packet2_bytes = create_tcp_packet('192.168.1.1', '192.168.1.100', 443, 54321, tls_record2)
    
    packet1 = pd.DataFrame({
        'src_ip': ['192.168.1.100'],
        'dst_ip': ['192.168.1.1'],
        'src_port': [54321],
        'dst_port': [443],
        'protocol': ['tcp'],
        'direction': [0],
        'packet_bytes': [packet1_bytes],
    })
    
    packet2 = pd.DataFrame({
        'src_ip': ['192.168.1.1'],
        'dst_ip': ['192.168.1.100'],
        'src_port': [443],
        'dst_port': [54321],
        'protocol': ['tcp'],
        'direction': [1],
        'packet_bytes': [packet2_bytes],
    })
    
    # Extract features
    features = extract_tls_features_from_packet_sequence([packet1, packet2])
    
    print(f"\n✅ Synthetic Test Results:")
    print(f"   - Features shape: {features.shape}")
    print(f"   - First 10 (tls_b_0-9): {features[0][:10]}")
    print(f"   - Next 10 (tls_dir_0-9): {features[0][10:20]}")
    
    # Expected: first record size=100, direction=0
    if features[0][0] == 100.0 and features[0][10] == 0.0:
        print(f"\n   ✅ Test passed! Features match expected values")
    else:
        print(f"\n   ⚠️  Test results: size={features[0][0]} (expected 100), dir={features[0][10]} (expected 0)")


if __name__ == "__main__":
    main()

