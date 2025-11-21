#!/usr/bin/env python3
"""
Production Cleanup Script
Removes test files and temporary artifacts for production deployment.
"""

import os
import glob
import shutil

# Test files to remove
test_patterns = [
    'test_*.py',
    'automated_bob.py',
    'demo_e2e.py',
    'run_demo.py',
]

# Individual files to remove
individual_files = [
    'server.log',
    'trusted_keys.json',
    'hello',
    '[E2E]',
    'TESTING.md',
    'cleanup_plan.txt'
]

def cleanup():
    """Remove test and temporary files."""
    removed = []
    
    # Remove pattern-matched files
    for pattern in test_patterns:
        for file in glob.glob(pattern):
            if os.path.exists(file):
                try:
                    os.remove(file)
                    removed.append(file)
                    print(f"Removed: {file}")
                except Exception as e:
                    print(f"Could not remove {file}: {e}")
    
    # Remove individual files
    for file in individual_files:
        if os.path.exists(file):
            try:
                if os.path.isfile(file):
                    os.remove(file)
                    removed.append(file)
                    print(f"Removed: {file}")
                elif os.path.isdir(file):
                    shutil.rmtree(file)
                    removed.append(file)
                    print(f"Removed directory: {file}")
            except Exception as e:
                print(f"Could not remove {file}: {e}")
    
    print(f"\n✅ Cleanup complete! Removed {len(removed)} items.")
    print("\nProduction-ready! Core files:")
    print("  ✓ server.py")
    print("  ✓ client_v2.py")
    print("  ✓ x3dh.py")
    print("  ✓ double_ratchet.py")
    print("  ✓ x25519_utils.py")
    print("  ✓ crypto_utils.py")
    print("  ✓ README.md")
    print("  ✓ LICENSE")

if __name__ == '__main__':
    print("Production Cleanup")
    print("=" * 60)
    print("This will remove test files and temporary artifacts.")
    print("=" * 60)
    
    response = input("\nProceed with cleanup? (yes/no): ").strip().lower()
    if response == 'yes':
        cleanup()
    else:
        print("Cleanup cancelled.")
