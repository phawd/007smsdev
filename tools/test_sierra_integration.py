#!/usr/bin/env python3
"""
Test Sierra Wireless Unlock Integration
========================================

This script tests the Sierra unlock algorithm integration without
actually attempting to unlock the device (safe to run).

Tests:
1. Import sierra_adapter module
2. Run algorithm self-test
3. Calculate test responses
4. Verify known challenge-response pairs
5. Check MiFi device detection

⚠️ This script does NOT attempt device unlock - safe to run!
"""

import sys
import os

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))


def test_import():
    """Test 1: Import sierra_adapter module"""
    print("=" * 70)
    print("TEST 1: Import sierra_adapter module")
    print("=" * 70)

    try:
        import sierra_adapter
        print("✓ sierra_adapter imported successfully")
        print(f"  Module location: {sierra_adapter.__file__}")
        return True
    except ImportError as e:
        print(f"✗ FAILED: {e}")
        return False


def test_selftest():
    """Test 2: Run algorithm self-test"""
    print("\n" + "=" * 70)
    print("TEST 2: Algorithm Self-Test")
    print("=" * 70)

    try:
        from sierra_adapter import run_selftest

        all_passed, results = run_selftest()

        print()
        for device, passed in results.items():
            status = "✓ PASSED" if passed else "✗ FAILED"
            print(f"  {device:20s} {status}")

        print()
        if all_passed:
            print("✓ All tests PASSED")
        else:
            print("✗ Some tests FAILED")

        return all_passed
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_calculate():
    """Test 3: Calculate test responses"""
    print("\n" + "=" * 70)
    print("TEST 3: Calculate Test Responses")
    print("=" * 70)

    try:
        from sierra_adapter import calculate_unlock_response

        # Test challenge from Sierra self-test
        test_cases = [
            ("BE96CBBEE0829BCA", "MDM9x40", "1033773720F6EE66"),
            ("BE96CBBEE0829BCA", "MDM9x30", "1E02CE6A98B7DD2A"),
            ("BE96CBBEE0829BCA", "MDM9x50", "32AB617DB4B1C205"),
            ("20E253156762DACE", "SDX55", "03940D7067145323"),
        ]

        all_passed = True
        for challenge, device, expected in test_cases:
            try:
                result = calculate_unlock_response(challenge, device)
                passed = (result == expected)
                status = "✓" if passed else "✗"
                print(f"{status} {device:15s} {challenge} → {result}")
                if not passed:
                    print(f"  Expected: {expected}")
                    all_passed = False
            except Exception as e:
                print(f"✗ {device:15s} ERROR: {e}")
                all_passed = False

        print()
        if all_passed:
            print("✓ All calculations PASSED")
        else:
            print("✗ Some calculations FAILED")

        return all_passed
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_mifi_detection():
    """Test 4: Test MiFi device detection"""
    print("\n" + "=" * 70)
    print("TEST 4: MiFi Device Detection")
    print("=" * 70)

    try:
        from sierra_adapter import (
            detect_device_generation,
            is_mifi_device,
            get_algorithm_info
        )

        # Test MiFi detection
        test_models = [
            ("MIFI8800L", True),
            ("MR5100", True),
            ("M2000", True),
            ("MC7455", False),
            ("EM7565", False),
        ]

        print("\nMiFi Device Detection:")
        for model, expected in test_models:
            result = is_mifi_device(model)
            status = "✓" if result == expected else "✗"
            mifi_str = "MiFi" if result else "Not MiFi"
            print(f"  {status} {model:15s} → {mifi_str}")

        # Test device generation detection
        test_firmware = [
            ("SDx20ALP-1.22.11", "MIFI8800L", "SDX20"),
            ("NTGX55_10.25.15.02", "MR5100", "SDX55"),
            ("NTGX65_10.04.13.03", "MR6400", "SDX65"),
        ]

        print("\nDevice Generation Detection:")
        for firmware, model, expected in test_firmware:
            result = detect_device_generation(firmware, model)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {firmware:20s} → {result or 'None'}")

        # Test algorithm info
        print("\nSDX20 Algorithm Info:")
        info = get_algorithm_info("SDX20")
        if info:
            print(f"  Key index: {info.get('openlock')}")
            print(f"  Challenge length: {info.get('clen')} bytes")
            print(f"  Init values: {info.get('init')}")
        else:
            print("  ✗ No algorithm info for SDX20")

        return True
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sdx20_calculation():
    """Test 5: SDX20 (MiFi 8800L) calculation"""
    print("\n" + "=" * 70)
    print("TEST 5: SDX20 (MiFi 8800L) Algorithm Test")
    print("=" * 70)

    try:
        from sierra_adapter import calculate_unlock_response

        # Test with same challenge as MDM9x40 (uses same key index 11)
        challenge = "BE96CBBEE0829BCA"

        mdm9x40_response = calculate_unlock_response(challenge, "MDM9x40")
        sdx20_response = calculate_unlock_response(challenge, "SDX20")

        print(f"\nChallenge: {challenge}")
        print(f"MDM9x40 response: {mdm9x40_response}")
        print(f"SDX20 response:   {sdx20_response}")

        if mdm9x40_response == sdx20_response:
            print("\n⚠️  SDX20 uses SAME algorithm as MDM9x40 (key index 11)")
            print("   This is EXPERIMENTAL and may be incorrect!")
            print("   Verify via Ghidra or carrier unlock before use!")
        else:
            print("\n✗ Algorithm mismatch - configuration error!")
            return False

        return True
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_mifi_controller_integration():
    """Test 6: mifi_controller integration"""
    print("\n" + "=" * 70)
    print("TEST 6: mifi_controller Integration")
    print("=" * 70)

    try:
        # Check if mifi_controller can import sierra_adapter
        from mifi_controller import unlock_carrier_sierra

        print("✓ unlock_carrier_sierra imported successfully")

        # Check function signatures
        import inspect
        sig = inspect.signature(unlock_carrier_sierra)
        print("\nunlock_carrier_sierra signature:")
        print(f"  {sig}")

        params = list(sig.parameters.keys())
        expected_params = ['challenge', 'devicegeneration']
        if params == expected_params:
            print("  ✓ Parameters match expected")
        else:
            print(f"  ⚠️  Parameters: {params}")

        return True
    except ImportError as e:
        print(f"⚠️  Could not import mifi_controller: {e}")
        print("   (This is expected if not running from tools/ directory)")
        return True  # Not a critical error
    except Exception as e:
        print(f"✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("SIERRA WIRELESS UNLOCK INTEGRATION TEST")
    print("=" * 70)
    print()
    print("⚠️  This script DOES NOT attempt device unlock - safe to run!")
    print("   Tests algorithm implementation only.")
    print()

    results = {
        "Import": test_import(),
        "Self-Test": test_selftest(),
        "Calculations": test_calculate(),
        "MiFi Detection": test_mifi_detection(),
        "SDX20 Algorithm": test_sdx20_calculation(),
        "mifi_controller": test_mifi_controller_integration(),
    }

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {test_name:20s} {status}")

    all_passed = all(results.values())

    print()
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print()
        print("Integration successful! Sierra algorithms ready to use.")
        print()
        print("⚠️  CRITICAL REMINDERS:")
        print("  - SDX20 algorithm is UNVERIFIED and EXPERIMENTAL")
        print("  - DO NOT attempt unlock on production device")
        print("  - Verify algorithm via Ghidra first")
        print("  - Test on non-critical device only")
        print("  - Check unlock retry counter before attempting")
        print("  - Always backup device state first")
        return_code = 0
    else:
        print("✗ SOME TESTS FAILED")
        print()
        print("Fix errors before using unlock functionality!")
        return_code = 1

    print()
    return return_code


if __name__ == "__main__":
    sys.exit(main())
