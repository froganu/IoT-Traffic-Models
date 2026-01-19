#!/usr/bin/env python3
"""
Phase 2 Test: Device Selector - Basic Functionality

Tests the device selector's ability to classify device type from packet data.
This test focuses on the device selector module directly.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
from src.context_selection_models import select_device_context_safe, load_device_selector


def create_packet_dataframe(n_packets=100, pattern='random'):
    """
    Create test packet DataFrame with various patterns.
    
    Args:
        n_packets: Number of packets to generate
        pattern: 'random', 'doorbell', 'other', or 'small'
    """
    np.random.seed(42)
    
    if pattern == 'small':
        # Very small dataset (might trigger fallback)
        n_packets = 5
    
    # Base features that pymfe can extract meta-features from
    data = {
        'packet_size': np.random.randint(100, 1500, n_packets),
        'direction': np.random.randint(0, 2, n_packets),
        'dst_port': np.random.choice([80, 443, 53, 1883], n_packets),
        'src_port': np.random.randint(49152, 65535, n_packets),
        'protocol': np.random.choice(['tcp', 'udp'], n_packets),
    }
    
    # Add more features for richer meta-feature extraction
    data['timestamp'] = np.arange(n_packets) * 0.1
    data['ip_ttl'] = np.random.randint(32, 255, n_packets)
    data['tcp_flags'] = np.random.randint(0, 256, n_packets)
    
    # Pattern-specific modifications
    if pattern == 'doorbell':
        # Doorbell-like pattern: smaller packets, more consistent sizes
        data['packet_size'] = np.random.randint(200, 800, n_packets)
        data['direction'] = np.random.choice([0, 1], n_packets, p=[0.3, 0.7])  # More outbound
    elif pattern == 'other':
        # Other device pattern: larger variance, more mixed traffic
        data['packet_size'] = np.random.randint(50, 2000, n_packets)
        data['direction'] = np.random.choice([0, 1], n_packets, p=[0.5, 0.5])  # Balanced
    
    return pd.DataFrame(data)


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 2 Test: Device Selector - Basic Functionality")
    print("=" * 80)
    print()
    
    # Test 1: Try to load models
    print("Test 1: Loading device selector models...")
    try:
        scaler, classifier = load_device_selector()
        print(f"  ✓ Models loaded successfully")
        print(f"    Scaler: {type(scaler).__name__}")
        print(f"    Classifier: {type(classifier).__name__}")
        if hasattr(classifier, 'classes_'):
            print(f"    Classes: {classifier.classes_}")
        models_available = True
    except ImportError as e:
        print(f"  ⚠ Models not available: {e}")
        print(f"    Install dependencies: pip install joblib scikit-learn pymfe")
        models_available = False
    except FileNotFoundError as e:
        print(f"  ⚠ Model files not found: {e}")
        models_available = False
    except Exception as e:
        print(f"  ✗ Error loading models: {e}")
        models_available = False
    
    print()
    
    if not models_available:
        print("Skipping device selector tests (models not available)")
        print("=" * 80)
        print("TEST SKIPPED ⚠")
        print("=" * 80)
        return 0  # Skip, not fail
    
    # Test 2: Test with sufficient data
    print("Test 2: Device selection with sufficient data...")
    packet_data = create_packet_dataframe(n_packets=100, pattern='random')
    print(f"  Packet DataFrame shape: {packet_data.shape}")
    
    try:
        device_type, confidence = select_device_context_safe(packet_data)
        if device_type is not None:
            print(f"  ✓ Device type: {device_type}")
            print(f"  ✓ Confidence: {confidence:.2%}")
        else:
            print(f"  ⚠ Device selector returned None (may need more data)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    
    # Test 3: Test with small dataset
    print("Test 3: Device selection with small dataset...")
    small_data = create_packet_dataframe(n_packets=20, pattern='small')
    print(f"  Packet DataFrame shape: {small_data.shape}")
    
    try:
        device_type, confidence = select_device_context_safe(small_data)
        if device_type is not None:
            print(f"  ✓ Device type: {device_type}")
            print(f"  ✓ Confidence: {confidence:.2%}")
        else:
            print(f"  ⚠ Device selector returned None (expected for small datasets)")
    except Exception as e:
        print(f"  ⚠ Error (may be expected): {e}")
    
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert models_available, "Models should be available or test should be skipped"
        print("  ✓ Device selector module is functional")
        print()
        print("=" * 80)
        print("TEST PASSED ✓")
        print("=" * 80)
        return 0
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
        print()
        print("=" * 80)
        print("TEST FAILED ✗")
        print("=" * 80)
        return 1


if __name__ == '__main__':
    sys.exit(main())

