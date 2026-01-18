"""
MoE Pipeline Testing Infrastructure

Tests the three-phase pipeline:
1. Phase 1: Encryption Detection (encrypted or not)
2. Phase 2: Context Selection (which expert/model to use)
3. Phase 3: C2 Detection (is it C2 attack or not with confidence)

Each phase runs the full pipeline from the beginning.
"""

import unittest
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.moe import detect_c2, check_encryption, select_ai_model
from src.encryption_detector import analyze_packet, PacketResult


class PipelineTestBase(unittest.TestCase):
    """Base class for pipeline tests with common utilities."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_results = []
    
    def create_packet_dataframe(self, 
                               packet_sizes: List[int] = None,
                               directions: List[int] = None,
                               port: int = 443,
                               protocol: str = 'tcp') -> pd.DataFrame:
        """
        Create a test packet DataFrame.
        
        Args:
            packet_sizes: List of packet sizes
            directions: List of directions (0 or 1)
            port: Port number
            protocol: Protocol string
        
        Returns:
            DataFrame with packet features
        """
        if packet_sizes is None:
            packet_sizes = [500, 600, 550, 450, 500]
        if directions is None:
            directions = [1, 0, 1, 0, 1]
        
        # Create packet-level DataFrame
        data = {
            'packet_size': packet_sizes,
            'direction': directions,
            'dst_port': [port] * len(packet_sizes),
            'src_port': [54321] * len(packet_sizes),
            'protocol': [protocol] * len(packet_sizes),
        }
        
        # Add TLS features if needed (for encrypted traffic)
        if port == 443 and protocol == 'tcp':
            for i in range(min(10, len(packet_sizes))):
                data[f'tls_b_{i}'] = [packet_sizes[i] if i < len(packet_sizes) else 0]
                data[f'tls_dir_{i}'] = [directions[i] if i < len(directions) else 0]
        
        return pd.DataFrame(data)
    
    def create_tls_packet_bytes(self) -> bytes:
        """Create synthetic TLS packet bytes."""
        # TLS ClientHello record
        return bytes([
            0x16,  # Handshake
            0x03, 0x03,  # TLS 1.2
            0x00, 0x05,  # Length
            0x01,  # ClientHello
            0x00, 0x00, 0x01, 0x00
        ])
    
    def create_dns_packet_bytes(self) -> bytes:
        """Create synthetic DNS packet bytes."""
        return bytes([
            0x12, 0x34,  # Transaction ID
            0x01, 0x00,  # Flags
            0x00, 0x01,  # QDCOUNT
            0x00, 0x00,  # ANCOUNT
            0x00, 0x00,  # NSCOUNT
            0x00, 0x00,  # ARCOUNT
            0x03, ord('w'), ord('w'), ord('w'),
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
            0x03, ord('c'), ord('o'), ord('m'),
            0x00,
            0x00, 0x01,  # QTYPE
            0x00, 0x01   # QCLASS
        ])
    
    def record_test_result(self, phase: int, test_name: str, result: Dict[str, Any]):
        """Record test result for reporting."""
        self.test_results.append({
            'phase': phase,
            'test': test_name,
            'result': result
        })


class Phase1EncryptionDetectionTests(PipelineTestBase):
    """
    Phase 1: Test Encryption Detection
    
    Tests the first phase of the pipeline: determining if traffic is encrypted or not.
    Runs from the beginning of the pipeline.
    """
    
    def test_encrypted_tls_traffic(self):
        """Test detection of encrypted TLS traffic."""
        # Create TLS packet data
        packet_data = self.create_packet_dataframe(port=443, protocol='tcp')
        packet_bytes = self.create_tls_packet_bytes()
        
        # Run encryption detection
        is_encrypted, protocol_type = check_encryption(
            packet_data, 
            port=443, 
            protocol='tcp',
            packet_bytes=packet_bytes
        )
        
        # Assertions
        self.assertTrue(is_encrypted, "TLS traffic should be detected as encrypted")
        self.assertEqual(protocol_type, 'tls', "Protocol type should be TLS")
        
        self.record_test_result(1, 'encrypted_tls_traffic', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'expected': True,
            'passed': is_encrypted and protocol_type == 'tls'
        })
    
    def test_encrypted_quic_traffic(self):
        """Test detection of encrypted QUIC traffic."""
        # QUIC on UDP/443
        packet_data = self.create_packet_dataframe(port=443, protocol='udp')
        
        # Run encryption detection
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=443,
            protocol='udp'
        )
        
        # Assertions
        self.assertTrue(is_encrypted, "QUIC traffic should be detected as encrypted")
        
        self.record_test_result(1, 'encrypted_quic_traffic', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'expected': True,
            'passed': is_encrypted
        })
    
    def test_cleartext_dns_traffic(self):
        """Test detection of cleartext DNS traffic."""
        packet_data = self.create_packet_dataframe(port=53, protocol='udp')
        packet_bytes = self.create_dns_packet_bytes()
        
        # Run encryption detection
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=53,
            protocol='udp',
            packet_bytes=packet_bytes
        )
        
        # Assertions
        self.assertFalse(is_encrypted, "DNS traffic should be detected as not encrypted")
        self.assertIsNone(protocol_type, "Cleartext should have no protocol type")
        
        self.record_test_result(1, 'cleartext_dns_traffic', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'expected': False,
            'passed': not is_encrypted
        })
    
    def test_cleartext_http_traffic(self):
        """Test detection of cleartext HTTP traffic."""
        packet_data = self.create_packet_dataframe(port=80, protocol='tcp')
        
        # Run encryption detection
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=80,
            protocol='tcp'
        )
        
        # Assertions
        self.assertFalse(is_encrypted, "HTTP traffic should be detected as not encrypted")
        
        self.record_test_result(1, 'cleartext_http_traffic', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'expected': False,
            'passed': not is_encrypted
        })
    
    def test_unknown_traffic(self):
        """Test handling of unknown traffic."""
        packet_data = self.create_packet_dataframe(port=12345, protocol='tcp')
        
        # Run encryption detection
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=12345,
            protocol='tcp'
        )
        
        # Unknown traffic should default to not encrypted
        self.assertFalse(is_encrypted, "Unknown traffic should default to not encrypted")
        
        self.record_test_result(1, 'unknown_traffic', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'expected': False,
            'passed': not is_encrypted
        })


class Phase2ContextSelectionTests(PipelineTestBase):
    """
    Phase 2: Test Context Selection
    
    Tests the second phase: selecting which expert/model to use based on encryption status.
    Runs encryption detection first, then context selection.
    """
    
    def test_encrypted_tls_context_selection(self):
        """Test context selection for encrypted TLS traffic."""
        # Phase 1: Encryption detection
        packet_data = self.create_packet_dataframe(port=443, protocol='tcp')
        packet_bytes = self.create_tls_packet_bytes()
        
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=443,
            protocol='tcp',
            packet_bytes=packet_bytes
        )
        
        # Phase 2: Context selection
        model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
        
        # Assertions
        self.assertTrue(is_encrypted, "Should detect encryption")
        self.assertEqual(protocol_type, 'tls', "Should detect TLS")
        self.assertEqual(model_name, 'tls_model', "Should select TLS model")
        
        self.record_test_result(2, 'encrypted_tls_context_selection', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'model_selected': model_name,
            'expected_model': 'tls_model',
            'passed': model_name == 'tls_model'
        })
    
    def test_cleartext_dns_context_selection(self):
        """Test context selection for cleartext DNS traffic."""
        # Phase 1: Encryption detection
        packet_data = self.create_packet_dataframe(port=53, protocol='udp')
        packet_bytes = self.create_dns_packet_bytes()
        
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=53,
            protocol='udp',
            packet_bytes=packet_bytes
        )
        
        # Phase 2: Context selection
        model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
        
        # Assertions
        self.assertFalse(is_encrypted, "Should detect as not encrypted")
        self.assertEqual(model_name, 'dns_model', "Should select DNS model")
        
        self.record_test_result(2, 'cleartext_dns_context_selection', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'model_selected': model_name,
            'expected_model': 'dns_model',
            'passed': model_name == 'dns_model'
        })
    
    def test_cleartext_mqtt_context_selection(self):
        """Test context selection for cleartext MQTT traffic."""
        # Phase 1: Encryption detection
        packet_data = self.create_packet_dataframe(port=1883, protocol='tcp')
        
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=1883,
            protocol='tcp'
        )
        
        # Phase 2: Context selection
        model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
        
        # Assertions
        self.assertFalse(is_encrypted, "Should detect as not encrypted")
        self.assertEqual(model_name, 'mqtt_model', "Should select MQTT model")
        
        self.record_test_result(2, 'cleartext_mqtt_context_selection', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'model_selected': model_name,
            'expected_model': 'mqtt_model',
            'passed': model_name == 'mqtt_model'
        })
    
    def test_unknown_context_selection(self):
        """Test context selection for unknown traffic."""
        # Phase 1: Encryption detection
        packet_data = self.create_packet_dataframe(port=12345, protocol='tcp')
        
        is_encrypted, protocol_type = check_encryption(
            packet_data,
            port=12345,
            protocol='tcp'
        )
        
        # Phase 2: Context selection
        model_name = select_ai_model(packet_data, is_encrypted, protocol_type)
        
        # Assertions
        self.assertFalse(is_encrypted, "Should default to not encrypted")
        # Should select default model or handle unknown
        self.assertIsNotNone(model_name, "Should select some model")
        
        self.record_test_result(2, 'unknown_context_selection', {
            'is_encrypted': is_encrypted,
            'protocol_type': protocol_type,
            'model_selected': model_name,
            'passed': model_name is not None
        })


class Phase3C2DetectionTests(PipelineTestBase):
    """
    Phase 3: Test C2 Detection
    
    Tests the third phase: detecting if traffic is C2 attack or not with confidence.
    Runs full pipeline: encryption detection → context selection → C2 prediction.
    """
    
    def test_encrypted_tls_c2_detection(self):
        """Test C2 detection for encrypted TLS traffic."""
        # Full pipeline test
        packet_data = self.create_packet_dataframe(port=443, protocol='tcp')
        packet_bytes = self.create_tls_packet_bytes()
        
        # Run full pipeline
        result = detect_c2(
            packet_data,
            port=443,
            protocol='tcp',
            packet_bytes=packet_bytes
        )
        
        # Assertions
        self.assertIsNotNone(result, "Should return a result")
        self.assertIn('is_encrypted', result, "Should have encryption status")
        self.assertIn('model_used', result, "Should have model selection")
        self.assertIn('is_c2', result, "Should have C2 prediction")
        
        # Phase 1 check
        self.assertTrue(result['is_encrypted'], "Should detect encryption")
        self.assertEqual(result['protocol_type'], 'tls', "Should detect TLS")
        
        # Phase 2 check
        self.assertEqual(result['model_used'], 'tls_model', "Should select TLS model")
        
        # Phase 3 check (prediction may be None if models not loaded)
        # This is expected in skeleton - models need to be implemented
        self.assertIn('is_c2', result, "Should have C2 prediction field")
        
        self.record_test_result(3, 'encrypted_tls_c2_detection', {
            'is_encrypted': result['is_encrypted'],
            'protocol_type': result['protocol_type'],
            'model_used': result['model_used'],
            'is_c2': result.get('is_c2'),
            'probability': result.get('probability'),
            'passed': result['is_encrypted'] and result['model_used'] == 'tls_model'
        })
    
    def test_cleartext_dns_c2_detection(self):
        """Test C2 detection for cleartext DNS traffic."""
        # Full pipeline test
        packet_data = self.create_packet_dataframe(port=53, protocol='udp')
        packet_bytes = self.create_dns_packet_bytes()
        
        # Run full pipeline
        result = detect_c2(
            packet_data,
            port=53,
            protocol='udp',
            packet_bytes=packet_bytes
        )
        
        # Assertions
        self.assertFalse(result['is_encrypted'], "Should detect as not encrypted")
        self.assertEqual(result['model_used'], 'dns_model', "Should select DNS model")
        self.assertIn('is_c2', result, "Should have C2 prediction")
        
        self.record_test_result(3, 'cleartext_dns_c2_detection', {
            'is_encrypted': result['is_encrypted'],
            'model_used': result['model_used'],
            'is_c2': result.get('is_c2'),
            'probability': result.get('probability'),
            'passed': not result['is_encrypted'] and result['model_used'] == 'dns_model'
        })
    
    def test_cleartext_mqtt_c2_detection(self):
        """Test C2 detection for cleartext MQTT traffic."""
        # Full pipeline test
        packet_data = self.create_packet_dataframe(port=1883, protocol='tcp')
        
        # Run full pipeline
        result = detect_c2(
            packet_data,
            port=1883,
            protocol='tcp'
        )
        
        # Assertions
        self.assertFalse(result['is_encrypted'], "Should detect as not encrypted")
        self.assertEqual(result['model_used'], 'mqtt_model', "Should select MQTT model")
        
        self.record_test_result(3, 'cleartext_mqtt_c2_detection', {
            'is_encrypted': result['is_encrypted'],
            'model_used': result['model_used'],
            'is_c2': result.get('is_c2'),
            'passed': not result['is_encrypted'] and result['model_used'] == 'mqtt_model'
        })
    
    def test_unknown_traffic_c2_detection(self):
        """Test C2 detection for unknown traffic."""
        # Full pipeline test
        packet_data = self.create_packet_dataframe(port=12345, protocol='tcp')
        
        # Run full pipeline
        result = detect_c2(
            packet_data,
            port=12345,
            protocol='tcp'
        )
        
        # Assertions
        self.assertFalse(result['is_encrypted'], "Should default to not encrypted")
        self.assertIn('model_used', result, "Should select a model")
        self.assertIn('is_c2', result, "Should have C2 prediction")
        
        self.record_test_result(3, 'unknown_traffic_c2_detection', {
            'is_encrypted': result['is_encrypted'],
            'model_used': result['model_used'],
            'is_c2': result.get('is_c2'),
            'passed': True  # Unknown should still complete pipeline
        })


class PipelineTestRunner:
    """
    Test runner for MoE pipeline phases.
    
    Can run individual phases or all phases together.
    """
    
    def __init__(self):
        """Initialize test runner."""
        self.suite = unittest.TestSuite()
        self.results = {}
    
    def add_phase(self, phase: int):
        """
        Add a phase to test suite.
        
        Args:
            phase: Phase number (1, 2, or 3)
        """
        if phase == 1:
            loader = unittest.TestLoader()
            tests = loader.loadTestsFromTestCase(Phase1EncryptionDetectionTests)
            self.suite.addTests(tests)
        elif phase == 2:
            loader = unittest.TestLoader()
            tests = loader.loadTestsFromTestCase(Phase2ContextSelectionTests)
            self.suite.addTests(tests)
        elif phase == 3:
            loader = unittest.TestLoader()
            tests = loader.loadTestsFromTestCase(Phase3C2DetectionTests)
            self.suite.addTests(tests)
        else:
            raise ValueError(f"Invalid phase: {phase}. Must be 1, 2, or 3")
    
    def add_all_phases(self):
        """Add all phases to test suite."""
        for phase in [1, 2, 3]:
            self.add_phase(phase)
    
    def run(self, verbosity: int = 2):
        """
        Run the test suite.
        
        Args:
            verbosity: Test verbosity level
        
        Returns:
            TestResult object
        """
        runner = unittest.TextTestRunner(verbosity=verbosity)
        result = runner.run(self.suite)
        self.results = result
        return result
    
    def print_summary(self):
        """Print test summary."""
        if not self.results:
            print("No test results available. Run tests first.")
            return
        
        print("\n" + "=" * 80)
        print("PIPELINE TEST SUMMARY")
        print("=" * 80)
        print(f"Tests run: {self.results.testsRun}")
        print(f"Failures: {len(self.results.failures)}")
        print(f"Errors: {len(self.results.errors)}")
        print(f"Successes: {self.results.testsRun - len(self.results.failures) - len(self.results.errors)}")
        print(f"Success rate: {(self.results.testsRun - len(self.results.failures) - len(self.results.errors)) / self.results.testsRun * 100:.1f}%")
        
        if self.results.failures:
            print("\nFailures:")
            for test, traceback in self.results.failures:
                print(f"  - {test}")
        
        if self.results.errors:
            print("\nErrors:")
            for test, traceback in self.results.errors:
                print(f"  - {test}")


def main():
    """Main entry point for running pipeline tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run MoE Pipeline Tests')
    parser.add_argument(
        '--phase',
        type=int,
        choices=[1, 2, 3],
        help='Run specific phase (1=Encryption, 2=Context, 3=C2 Detection)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all phases'
    )
    parser.add_argument(
        '--verbosity',
        type=int,
        default=2,
        help='Test verbosity (0=quiet, 1=normal, 2=verbose)'
    )
    
    args = parser.parse_args()
    
    runner = PipelineTestRunner()
    
    if args.all:
        runner.add_all_phases()
    elif args.phase:
        runner.add_phase(args.phase)
    else:
        # Default: run all phases
        runner.add_all_phases()
    
    result = runner.run(verbosity=args.verbosity)
    runner.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()

