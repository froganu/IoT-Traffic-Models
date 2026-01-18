#!/usr/bin/env python3
"""
Test runner script for MoE Pipeline.

Provides convenient interface for running pipeline tests with different configurations.
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.test_pipeline import PipelineTestRunner


def run_phase_tests(phase: int, verbosity: int = 2):
    """
    Run tests for a specific phase.
    
    Args:
        phase: Phase number (1, 2, or 3)
        verbosity: Test verbosity level
    """
    print(f"\n{'=' * 80}")
    print(f"RUNNING PHASE {phase} TESTS")
    print(f"{'=' * 80}\n")
    
    runner = PipelineTestRunner()
    runner.add_phase(phase)
    result = runner.run(verbosity=verbosity)
    runner.print_summary()
    
    return result.wasSuccessful()


def run_all_phases(verbosity: int = 2):
    """
    Run all phase tests sequentially.
    
    Args:
        verbosity: Test verbosity level
    """
    print("\n" + "=" * 80)
    print("RUNNING ALL PHASE TESTS")
    print("=" * 80)
    
    results = {}
    
    for phase in [1, 2, 3]:
        success = run_phase_tests(phase, verbosity=verbosity)
        results[phase] = success
        print()
    
    # Print final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    for phase, success in results.items():
        status = "PASSED" if success else "FAILED"
        print(f"Phase {phase}: {status}")
    
    all_passed = all(results.values())
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    return all_passed


def run_integration_tests(verbosity: int = 2):
    """
    Run integration tests (all phases together).
    
    Args:
        verbosity: Test verbosity level
    """
    print("\n" + "=" * 80)
    print("RUNNING INTEGRATION TESTS (ALL PHASES)")
    print("=" * 80)
    
    runner = PipelineTestRunner()
    runner.add_all_phases()
    result = runner.run(verbosity=verbosity)
    runner.print_summary()
    
    return result.wasSuccessful()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='MoE Pipeline Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run Phase 1 tests only
  python tests/run_tests.py --phase 1
  
  # Run Phase 2 tests only
  python tests/run_tests.py --phase 2
  
  # Run Phase 3 tests only
  python tests/run_tests.py --phase 3
  
  # Run all phases sequentially
  python tests/run_tests.py --all-phases
  
  # Run integration tests (all phases together)
  python tests/run_tests.py --integration
  
  # Run with quiet output
  python tests/run_tests.py --phase 1 --verbosity 0
        """
    )
    
    parser.add_argument(
        '--phase',
        type=int,
        choices=[1, 2, 3],
        help='Run specific phase tests (1=Encryption, 2=Context, 3=C2 Detection)'
    )
    
    parser.add_argument(
        '--all-phases',
        action='store_true',
        help='Run all phases sequentially'
    )
    
    parser.add_argument(
        '--integration',
        action='store_true',
        help='Run integration tests (all phases together)'
    )
    
    parser.add_argument(
        '--verbosity',
        type=int,
        default=2,
        choices=[0, 1, 2],
        help='Test verbosity (0=quiet, 1=normal, 2=verbose)'
    )
    
    args = parser.parse_args()
    
    # Determine what to run
    if args.phase:
        success = run_phase_tests(args.phase, verbosity=args.verbosity)
    elif args.all_phases:
        success = run_all_phases(verbosity=args.verbosity)
    elif args.integration:
        success = run_integration_tests(verbosity=args.verbosity)
    else:
        # Default: run all phases sequentially
        success = run_all_phases(verbosity=args.verbosity)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

