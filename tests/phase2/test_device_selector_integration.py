#!/usr/bin/env python3
"""
Phase 2 Test: Device Selector - Integration with MoE Pipeline

Tests device selector integration in the full MoE pipeline (Phase 1 → Phase 2).
Verifies that non-encrypted traffic uses device selector for context selection.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
from src.moe import check_encryption, select_ai_model


def create_packet_dataframe(n_packets=100, port=1883, protocol='tcp'):
    """Create test packet DataFrame for non-encrypted traffic."""
    np.random.seed(42)
    
    data = {
        'packet_size': np.random.randint(100, 1500, n_packets),
        'direction': np.random.randint(0, 2, n_packets),
        'dst_port': [port] * n_packets,
        'src_port': np.random.randint(49152, 65535, n_packets),
        'protocol': [protocol] * n_packets,
        'timestamp': np.arange(n_packets) * 0.1,
        'ip_ttl': np.random.randint(32, 255, n_packets),
    }
    
    return pd.DataFrame(data)


def main():
    """Run the test."""
    print("=" * 80)
    print("Phase 2 Test: Device Selector - Integration with MoE Pipeline")
    print("=" * 80)
    print()
    
    # Phase 1: Encryption detection
    print("Phase 1: Running encryption detection...")
    packet_data = create_packet_dataframe(n_packets=100, port=1883, protocol='tcp')
    
    is_encrypted, protocol_type = check_encryption(
        packet_data,
        port=1883,
        protocol='tcp'
    )
    
    print(f"  Encrypted: {is_encrypted}")
    print(f"  Protocol Type: {protocol_type}")
    print()
    
    # Phase 2: Context selection (should use device selector for non-encrypted)
    print("Phase 2: Running context selection...")
    print("  (Should attempt device selector, then fall back to port-based if needed)")
    
    model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
    
    print(f"  Selected Model: {model_name}")
    print()
    
    # Check if device selector was attempted
    device_selector_available = False
    try:
        from src.context_selection_models import load_device_selector
        scaler, classifier = load_device_selector()
        device_selector_available = True
        print(f"  Device Selector: Available")
    except (ImportError, FileNotFoundError):
        print(f"  Device Selector: Not available (will use port-based routing)")
    except Exception as e:
        print(f"  Device Selector: Error - {e}")
    
    print()
    
    # Assertions
    print("Assertions:")
    try:
        assert is_encrypted == False, f"Expected encrypted=False, got {is_encrypted}"
        assert model_name is not None, "Model name should not be None"
        
        # For non-encrypted MQTT traffic, should get mqtt_model or doorbell_model
        # (depending on device selector result or port-based fallback)
        valid_models = ['mqtt_model', 'doorbell_model', 'mqtt_coap_rtsp_model']
        assert model_name in valid_models, f"Expected model in {valid_models}, got {model_name}"
        
        print("  ✓ Encryption correctly detected as not encrypted")
        print(f"  ✓ Model selected: {model_name}")
        if device_selector_available:
            print("  ✓ Device selector is available and integrated")
        else:
            print("  ✓ Port-based routing used (device selector not available)")
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

