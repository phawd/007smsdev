# Sierra Unlock Quick Reference

## ⚠️ READ THIS FIRST

**ALGORITHM UNVERIFIED**: Sierra algorithms designed for Sierra Wireless chipsets, NOT Qualcomm SDX20 (MiFi 8800L). Wrong algorithm = permanent device lock.

**DO NOT UNLOCK PRODUCTION DEVICE!**

## Quick Commands

### Check Unlock Status (SAFE)

```python
python -c "
from mifi_controller import get_carrier_unlock_status
success, status = get_carrier_unlock_status()
if success:
    print(f'State: {\"Locked\" if status[\"state\"] else \"Unlocked\"}')
    print(f'Retries: {status[\"verify_retries\"]}')
"
```

### Run Self-Test (SAFE)

```bash
python sierra_adapter.py
```

### Test Integration (SAFE)

```bash
python test_sierra_integration.py
```

### Calculate Response (SAFE - No Device)

```python
from sierra_adapter import calculate_unlock_response
response = calculate_unlock_response("BE96CBBEE0829BCA", "SDX20")
print(response)  # 1033773720F6EE66
```

### Attempt Unlock (HIGH RISK)

```python
from mifi_controller import unlock_carrier_sierra
success, output = unlock_carrier_sierra()  # Interactive prompts
```

## Pre-Unlock Checklist

- [ ] Device is NOT critical (test device only)
- [ ] Retry counter > 5 (check with get_carrier_unlock_status)
- [ ] Full backup completed (IMEI, EFS, NV items)
- [ ] Algorithm verified via Ghidra OR carrier unlock capture
- [ ] Typed "UNLOCK" to confirm understanding of risk

## Files

```
tools/
├── sierra_adapter.py          - Core algorithms
├── mifi_controller.py         - Device interface
└── test_sierra_integration.py - Test suite

docs/
├── SIERRA_UNLOCK_INTEGRATION.md  - Full documentation
└── SESSION_5_SUMMARY.md          - Session summary
```

## Algorithm Info

| Device | Generation | Key Index | Verified |
|--------|------------|-----------|----------|
| MiFi 8800L | SDX20 | 11 | ❌ NO |
| MiFi M2000 | SDX55 | 22 | ❌ NO |
| MiFi M2100 | SDX65 | 25 | ❌ NO |

**All MiFi algorithms UNVERIFIED!**

## Safety

✓ Self-test passing (8/8)
✓ Integration tests passing (6/6)
✓ Safety checks implemented
❌ Algorithm not verified for Qualcomm SDX20
❌ No test device available
❌ Retry counter unknown

## Next Steps

1. Query retry counter: `get_carrier_unlock_status()`
2. If counter > 5: Consider testing (HIGH RISK)
3. If counter ≤ 5: DO NOT ATTEMPT (too risky)
4. Better: Verify algorithm via Ghidra first
5. Best: Request carrier unlock (legitimate method)

## Support

- Full docs: `docs/SIERRA_UNLOCK_INTEGRATION.md`
- Session summary: `docs/SESSION_5_SUMMARY.md`
- MiFi guide: `docs/MIFI_DEVICE_GUIDE.md`
