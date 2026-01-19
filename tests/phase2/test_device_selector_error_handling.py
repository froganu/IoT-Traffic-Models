#!/usr/bin/env python3
"""
Phase 2 Test: Device Selector - Error Handling

Tests device selector's error handling for edge cases:
- Empty DataFrames
- Very small datasets
- Missing dependencies
- Invalid data
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
from src.context_selection_models import select_device_context_safe


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 2 Test: Device Selector - Error Handling")
    print("=" * 80)
    print()
    
    test_results = []
    
    # Test 1: Empty DataFrame
    print("Test 1: Empty DataFrame...")
    try:
        empty_df = pd.DataFrame()
        device_type, confidence = select_device_context_safe(empty_df)
        if device_type is None:
            print("  ✓ Handled gracefully (returned None)")
            test_results.append(True)
        else:
            print(f"  ⚠ Unexpected result: {device_type}")
            test_results.append(False)
    except Exception as e:
        print(f"  ✗ Error not handled: {e}")
        test_results.append(False)
    
    print()
    
    # Test 2: Very small dataset (< 10 rows)
    print("Test 2: Very small dataset (5 rows)...")
    try:
        small_df = pd.DataFrame({
            'packet_size': [100, 200, 150, 180, 120],
            'direction': [1, 0, 1, 0, 1],
            'dst_port': [80, 80, 80, 80, 80],
        })
        device_type, confidence = select_device_context_safe(small_df)
        # Should handle gracefully (may return None or work with minimal features)
        print(f"  ✓ Handled gracefully: device_type={device_type}, confidence={confidence}")
        test_results.append(True)
    except Exception as e:
        print(f"  ✗ Error not handled: {e}")
        test_results.append(False)
    
    print()
    
    # Test 3: Single row
    print("Test 3: Single row dataset...")
    try:
        single_df = pd.DataFrame({
            'packet_size': [500],
            'direction': [1],
            'dst_port': [443],
        })
        device_type, confidence = select_device_context_safe(single_df)
        print(f"  ✓ Handled gracefully: device_type={device_type}, confidence={confidence}")
        test_results.append(True)
    except Exception as e:
        print(f"  ✗ Error not handled: {e}")
        test_results.append(False)
    
    print()
    
    # Test 4: Missing columns (minimal features)
    print("Test 4: Minimal features (only packet_size)...")
    try:
        minimal_df = pd.DataFrame({
            'packet_size': np.random.randint(100, 1500, 50),
        })
        device_type, confidence = select_device_context_safe(minimal_df)
        print(f"  ✓ Handled gracefully: device_type={device_type}, confidence={confidence}")
        test_results.append(True)
    except Exception as e:
        print(f"  ✗ Error not handled: {e}")
        test_results.append(False)
    
    print()
    
    # Test 5: Normal dataset (should work if models available)
    print("Test 5: Normal dataset (100 packets)...")
    try:
        normal_df = pd.DataFrame({
            'packet_size': np.random.randint(100, 1500, 100),
            'direction': np.random.randint(0, 2, 100),
            'dst_port': np.random.choice([80, 443, 53], 100),
            'src_port': np.random.randint(49152, 65535, 100),
            'protocol': np.random.choice(['tcp', 'udp'], 100),
        })
        device_type, confidence = select_device_context_safe(normal_df)
        if device_type is not None:
            print(f"  ✓ Worked: device_type={device_type}, confidence={confidence:.2%}")
        else:
            print(f"  ⚠ Returned None (models may not be available)")
        test_results.append(True)  # Not an error if None (models not available)
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        test_results.append(False)
    
    print()
    
    # Assertions
    print("Assertions:")
    try:
        all_passed = all(test_results)
        assert all_passed, f"Some tests failed: {test_results}"
        print("  ✓ All error handling tests passed")
        print("  ✓ Device selector handles edge cases gracefully")
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

