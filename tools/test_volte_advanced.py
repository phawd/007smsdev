#!/usr/bin/env python3
"""
Test VoLTE Advanced Functions

Tests the newly implemented VoLTE advanced and IMS configuration functions.
"""

from mifi_controller import (
    volte_get_amr_mode,
    volte_get_amr_wb_mode,
    volte_get_dcmo_timer,
    volte_get_dcmo_tdelay,
    volte_get_hys,
    volte_get_rcl_max_entries,
    volte_get_sess_config,
    volte_get_silent_redial,
    volte_get_src_thttle,
    volte_get_tlte_911fail,
    ims_pres_get_config,
)


def main():
    """Test all VoLTE advanced and IMS functions."""
    print("=" * 60)
    print("Testing VoLTE Advanced Functions")
    print("=" * 60)
    print()

    # AMR Codec Modes
    print("=== AMR Codec Modes ===")
    try:
        amr_mode = volte_get_amr_mode()
        print(f"AMR Mode: {amr_mode}")
    except Exception as e:
        print(f"AMR Mode: ERROR - {e}")

    try:
        amr_wb_mode = volte_get_amr_wb_mode()
        print(f"AMR-WB Mode: {amr_wb_mode}")
    except Exception as e:
        print(f"AMR-WB Mode: ERROR - {e}")
    print()

    # DCMO Timers
    print("=== DCMO Timers ===")
    try:
        dcmo_timer = volte_get_dcmo_timer()
        print(f"DCMO Timer: {dcmo_timer}s")
    except Exception as e:
        print(f"DCMO Timer: ERROR - {e}")

    try:
        dcmo_tdelay = volte_get_dcmo_tdelay()
        print(f"DCMO Delay: {dcmo_tdelay}ms")
    except Exception as e:
        print(f"DCMO Delay: ERROR - {e}")
    print()

    # Hysteresis & RCL
    print("=== Hysteresis & RCL ===")
    try:
        hys = volte_get_hys()
        print(f"Hysteresis: {hys}")
    except Exception as e:
        print(f"Hysteresis: ERROR - {e}")

    try:
        rcl_max = volte_get_rcl_max_entries()
        print(f"RCL Max Entries: {rcl_max}")
    except Exception as e:
        print(f"RCL Max Entries: ERROR - {e}")
    print()

    # Session Config
    print("=== Session Config ===")
    try:
        sess_config = volte_get_sess_config()
        print(f"Session Config: {sess_config}")
    except Exception as e:
        print(f"Session Config: ERROR - {e}")
    print()

    # Call Features
    print("=== Call Features ===")
    try:
        silent_redial = volte_get_silent_redial()
        print(f"Silent Redial: {silent_redial}")
    except Exception as e:
        print(f"Silent Redial: ERROR - {e}")

    try:
        src_thttle = volte_get_src_thttle()
        print(f"Source Throttle: {src_thttle}")
    except Exception as e:
        print(f"Source Throttle: ERROR - {e}")

    try:
        tlte_911fail = volte_get_tlte_911fail()
        print(f"LTE 911 Fail Timer: {tlte_911fail}s")
    except Exception as e:
        print(f"LTE 911 Fail Timer: ERROR - {e}")
    print()

    # IMS Presence Config
    print("=== IMS Presence Config ===")
    try:
        pres_config = ims_pres_get_config()
        print(f"Presence Config: {pres_config}")
    except Exception as e:
        print(f"Presence Config: ERROR - {e}")
    print()

    print("=" * 60)
    print("VoLTE Advanced Function Tests Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
