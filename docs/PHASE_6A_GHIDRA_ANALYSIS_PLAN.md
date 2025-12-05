# Phase 6A: SPC Algorithm Reversal - Ghidra Analysis Plan

## Objective

Reverse-engineer the SPC validation algorithm and all proprietary lock-related library calls in MiFi 8800L firmware.

---

## Target Libraries

- `libmal_qct.so` (307 KB) - QMI protocol, SPC validation
- `libmodem2_api.so` (144 KB) - Userspace lock API

---

## Key Functions to Analyze

### In `libmal_qct.so`

- `nwqmi_dms_validate_spc` (CORE TARGET)
- `nwqmi_uim_verify_pin` (SIM PIN validation)
- `nwqmi_uim_unblock_pin` (SIM PUK unblocking)
- `nwqmi_dms_get_spc_validate_limit` (SPC attempt limit)
- `nwqmi_dms_get_spc_code` (SPC retrieval)
- Any function referencing NV items or IMEI

### In `libmodem2_api.so`

- `modem2_validate_spc_code` (userspace SPC validation)
- `modem2_carrier_unlock` (carrier unlock)
- `modem2_sim_unlock_pin` (SIM PIN unlock)
- `modem2_sim_unlock_puk` (SIM PUK unlock)
- `modem2_get_certified_carrier` (carrier config)

---

## Ghidra Workflow

1. Import both libraries as ARM binaries
2. Auto-analyze and identify all exported functions
3. Locate string references for 'spc', 'unlock', 'carrier', 'imei', 'nv', 'pin', 'puk', 'block'
4. Map call graphs for all lock-related functions
5. Decompile `nwqmi_dms_validate_spc` and trace input parameters
6. Identify if SPC is IMEI-derived, static, or random
7. Document all proprietary function flows
8. Prepare Python code for SPC calculation if derivable
9. Document findings for ZeroSMS integration

---

## Deliverables

- SPC algorithm documentation (step-by-step logic)
- Call graph diagrams for all lock-related functions
- Python SPC calculator (if possible)
- Technical report for ZeroSMS integration

---

## Next Steps

- Begin Ghidra analysis
- Systematically reverse all proprietary lock-related calls
- Document and prepare code artifacts

---

**Status:** Phase 6A plan created. Ready to commence Ghidra analysis.
