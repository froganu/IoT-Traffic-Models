#!/usr/bin/env python3
"""
Run all Phase 2 tests.

Executes all test scripts in this directory.
"""

import sys
import subprocess
from pathlib import Path


def main():
    """Run all Phase 2 tests."""
    phase2_dir = Path(__file__).parent
    
    # Find all test scripts (excluding __init__.py and this file)
    test_scripts = sorted([
        f for f in phase2_dir.glob('test_*.py')
        if f.name != 'run_all_tests.py'
    ])
    
    if not test_scripts:
        print("No test scripts found in phase2/")
        return 1
    
    print("=" * 80)
    print("RUNNING ALL PHASE 2 TESTS")
    print("=" * 80)
    print(f"\nFound {len(test_scripts)} test scripts\n")
    
    results = {}
    
    for test_script in test_scripts:
        print("-" * 80)
        print(f"Running: {test_script.name}")
        print("-" * 80)
        print()
        
        # Run test script
        result = subprocess.run(
            [sys.executable, str(test_script)],
            cwd=str(phase2_dir),
            capture_output=False
        )
        
        results[test_script.name] = result.returncode == 0
        print()
    
    # Summary
    print("=" * 80)
    print("PHASE 2 TEST SUMMARY")
    print("=" * 80)
    print()
    
    passed_count = sum(1 for p in results.values() if p)
    total = len(results)
    
    for test_name, test_passed in results.items():
        status = "PASSED ✓" if test_passed else "FAILED ✗"
        print(f"  {test_name:40s} {status}")
    
    print()
    print(f"Total: {passed_count}/{total} tests passed ({passed_count/total*100:.1f}%)")
    print()
    
    return 0 if passed_count == total else 1


if __name__ == '__main__':
    sys.exit(main())

