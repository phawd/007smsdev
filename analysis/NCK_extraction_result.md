# NCK Extraction Result: modem2_cli (Ghidra Headless Script)

## Summary

Automated Ghidra scripting was used to search for functions related to carrier unlock and NCK logic in the ARM binary `modem2_cli`. The following functions were identified:

- `modem2_carrier_unlock_status`
- `modem2_carrier_unlock`
- `modem2_sim_unlock_pin`
- `modem2_sim_unlock_puk`

## Decompiled Output (Key Functions)

All of these functions are thin wrappers that call function pointers, e.g.:

```c
void modem2_carrier_unlock(void) {
  (*(code *)PTR_modem2_carrier_unlock_0002bc6c)();
  return;
}
```

However, the actual logic is implemented in external code (likely in a shared library such as `libmodem2_api.so` or similar), and the function pointers are resolved at runtime. Ghidra was unable to decompile the underlying logic due to these being external calls.

## Warnings

- The real NCK calculation and unlock logic is not present in the main binary, but in external libraries loaded at runtime.
- To extract the NCK algorithm, you must analyze the relevant shared libraries (e.g., `libmodem2_api.so`, `libmal_qct.so`, etc.) found in the same directory as `modem2_cli`.
- The static binary alone does not contain the NCK algorithm.

## Rizin Analysis Results (Dec 2025)

Rizin (with extensions) was used to re-analyze all shared libraries and binaries in `/usr/src/repo/007smsdev/mifi_backup/binaries/`. The following key findings were observed:

- **libmodem2_api.so** and **libmal_qct.so** both export functions and strings directly related to carrier unlock and SIM unlock logic:
  - `modem2_carrier_unlock`, `modem2_carrier_unlock_status`, `modem2_sim_unlock_pin`, `modem2_sim_unlock_puk`, and related status/command strings.
  - These match the wrapper/imported functions seen in the main binary (`modem2_cli`).
- The Rizin symbol and string search confirms that the real logic for unlock/NCK is implemented in these shared libraries, not in the main binary.
- No direct NCK algorithm was found in symbol names, but all unlock-related entry points are present and can be targeted for deeper static or dynamic analysis.
- See `analysis/rizin_unlock_summary.txt` for the full cross-referenced output.

### Next Steps

1. Use Rizin or Ghidra to further decompile and analyze the bodies of the identified functions in the shared libraries, focusing on `modem2_carrier_unlock` and related symbols.
2. Cross-reference with the adapter logic in `sierra_adapter.py` for expected algorithm structure and data flow.
3. Consider dynamic analysis (e.g., emulation or tracing) if static analysis does not yield the NCK algorithm.

---
*This section summarizes the Rizin-assisted static analysis. The findings reinforce the previous Ghidra results and provide concrete entry points for further reverse engineering.*

---
*This result is based on automated Ghidra headless analysis. For deeper reverse engineering, dynamic analysis or further static analysis of the shared libraries is required.*
