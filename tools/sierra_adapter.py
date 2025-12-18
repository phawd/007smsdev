#!/usr/bin/env python3
"""
Sierra Wireless Unlock Algorithm Adapter for MiFi Devices
==========================================================

Adapts B.Kerler's Sierra Wireless unlock algorithms for Inseego MiFi devices.

Original Author: B.Kerler 2019-2023 (GPLv3)
Adapter: ZeroSMS Project 2024
License: GPLv3

WARNING: This module implements carrier unlock algorithms.
- Wrong NCK codes may permanently lock the device
- Requires valid challenge from modem first
- Some algorithms may not work on Qualcomm SDX20 (MiFi chipset)
- Always backup device state before attempting unlock

Architecture Notes:
- Sierra devices: MDM8200, MDM9200, MDM9x15/30/40/50, SDX55/65/75
- Inseego MiFi 8800L: Qualcomm SDX20 (Alpine) - NOT Sierra chipset
- Algorithm compatibility is UNCERTAIN - research required

Challenge-Response Process:
1. Query modem for unlock challenge: AT!OPENLOCK?
2. Device returns 8-byte hex challenge (e.g., BE96CBBEE0829BCA)
3. Calculate response using SierraAlgo with device-specific key
4. Submit response: AT!OPENLOCK="calculated_response"
5. If correct, device unlocks; if wrong, retry counter decrements

MiFi Command Equivalents:
- AT!OPENLOCK? → /opt/nvtl/bin/modem2_cli unlock_carrier_lock (get challenge)
- AT!OPENLOCK="response" → /opt/nvtl/bin/modem2_cli unlock_carrier_lock (submit)
"""

from binascii import hexlify, unhexlify
from typing import Dict, List, Tuple, Optional


# ============================================================================
# ALGORITHM TABLES (Sierra Wireless)
# ============================================================================

# Product table: Maps device generation to algorithm parameters
# - openlock: Key index for carrier unlock
# - openmep: Key index for MEP unlock (SIM personalization)
# - opencnd: Key index for conditional access
# - clen: Challenge length (bytes)
# - init: Initial register values [7, 3, 0, 1, 5]
# - run: Execution string (uses SierraAlgo)
PRODTABLE = {
    "MDM8200": dict(
        openlock=0, openmep=1, opencnd=0, clen=8, init=[1, 3, 5, 7, 0],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 2, 4, 1, 3, 0, 3, 4, 0)"
    ),
    "MDM9200": dict(
        openlock=0, openmep=2, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "MDM9200_V1": dict(
        openlock=2, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "MDM9200_V2": dict(
        openlock=3, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "MDM9x15": dict(
        openlock=0, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "MDM9x30": dict(
        openlock=5, openmep=4, opencnd=5, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "MDM9x40": dict(
        openlock=11, openmep=12, opencnd=11, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "MDM9x50": dict(
        openlock=7, openmep=6, opencnd=7, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
    "SDX55": dict(openlock=22, openmep=21, opencnd=22, clen=8, init=[7, 3, 0, 1, 5],
                  run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    "SDX65": dict(openlock=25, openmep=21, opencnd=26, clen=8, init=[7, 3, 0, 1, 5],
                  run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    # EXPERIMENTAL: SDX20 (MiFi 8800L) - algorithm unknown, trying MDM9x40 as closest
    "SDX20": dict(
        openlock=11, openmep=12, opencnd=11, clen=8, init=[7, 3, 0, 1, 5],
        run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"
    ),
}

# Device info table: Maps model names to device generations
INFOTABLE = {
    "MDM8200": ["M81A", "M81B", "AC880", "AC881", "MC8780", "MC8781"],
    "MDM9200": ["AC710", "MC8775", "MC7700", "MC7750", "MC7710", "EM7700"],
    "MDM9x15": ["SWI9X15C", "EM7355", "MC7354", "MC7305", "EM7305", "AC340U"],
    "MDM9x30": ["EM7455", "MC7455", "EM7430", "MC7430"],
    "MDM9x40": ["MR1100", "AC815s", "AC785s", "AC797S"],
    "MDM9x50": ["EM7565", "EM7565-9", "EM7511", "EM7411"],
    "SDX55": ["MR5100", "MR5200", "MR6400"],
    "SDX65": ["MR6400", "MR6500", "MR6110", "MR6150"],
    "SDX20": ["MIFI8800L", "8800L"],  # Inseego MiFi 8800L
}

# Key table: 29 keys x 16 bytes each = 464 bytes
# Each key is used for different device generations (indexed by openlock/openmep/opencnd)
KEYTABLE = bytearray([
    # Key 0: MDM8200/MDM9200/MDM9x15 OPENLOCK
    0xF0, 0x14, 0x55, 0x0D, 0x5E, 0xDA, 0x92, 0xB3, 0xA7, 0x6C, 0xCE, 0x84, 0x90, 0xBC, 0x7F, 0xED,
    # Key 1: MDM8200 OPENMEP, AC340U
    0x61, 0x94, 0xCE, 0xA7, 0xB0, 0xEA, 0x4F, 0x0A, 0x73, 0xC5, 0xC3, 0xA6, 0x5E, 0xEC, 0x1C, 0xE2,
    # Key 2: AC750, AC710, AC7XX OPENMEP
    0x39, 0xC6, 0x7B, 0x04, 0xCA, 0x50, 0x82, 0x1F, 0x19, 0x63, 0x36, 0xDE, 0x81, 0x49, 0xF0, 0xD7,
    # Key 3: AC775, PC7200
    0xDE, 0xA5, 0xAD, 0x2E, 0xBE, 0xE1, 0xC9, 0xEF, 0xCA, 0xF9, 0xFE, 0x1F, 0x17, 0xFE, 0xED, 0x3B,
    # Key 4: MC7455 OPENMEP
    0xFE, 0xD4, 0x40, 0x52, 0x2D, 0x4B, 0x12, 0x5C, 0xE7, 0x0D, 0xF8, 0x79, 0xF8, 0xC0, 0xDD, 0x37,
    # Key 5: MC7455 OPENLOCK
    0x3B, 0x18, 0x99, 0x6B, 0x57, 0x24, 0x0A, 0xD8, 0x94, 0x6F, 0x8E, 0xD9, 0x90, 0xBC, 0x67, 0x56,
    # Key 6: SWI9x50 OPENMEP
    0x47, 0x4F, 0x4F, 0x44, 0x4A, 0x4F, 0x42, 0x44, 0x45, 0x43, 0x4F, 0x44, 0x49, 0x4E, 0x47, 0x2E,
    # Key 7: SWI9x50 OPENLOCK ("OMAR DID THIS...")
    0x4F, 0x4D, 0x41, 0x52, 0x20, 0x44, 0x49, 0x44, 0x20, 0x54, 0x48, 0x49, 0x53, 0x2E, 0x2E, 0x2E,
    # Key 8: MDM8200 Special
    0x8F, 0xA5, 0x85, 0x05, 0x5E, 0xCF, 0x44, 0xA0, 0x98, 0x8B, 0x09, 0xE8, 0xBB, 0xC6, 0xF7, 0x65,
    # Key 9: SWI9x07 OPENLOCK
    0x4D, 0x42, 0xD8, 0xC1, 0x25, 0x44, 0xD8, 0xA0, 0x1D, 0x80, 0xC4, 0x52, 0x8E, 0xEC, 0x8B, 0xE3,
    # Key 10: SWI9x07 OPENMEP
    0xED, 0xA9, 0xB7, 0x0A, 0xDB, 0x85, 0x3D, 0xC0, 0x92, 0x49, 0x7D, 0x41, 0x9A, 0x91, 0x09, 0xEE,
    # Key 11: NTG9X40C / AC815s / MR1100 OPENLOCK
    0x8A, 0x56, 0x03, 0xF0, 0xBB, 0x9C, 0x13, 0xD2, 0x4E, 0xB2, 0x45, 0xAD, 0xC4, 0x0A, 0xE7, 0x52,
    # Key 12: MR1100 OPENMEP
    0x2A, 0xEF, 0x07, 0x2B, 0x19, 0x60, 0xC9, 0x01, 0x8B, 0x87, 0xF2, 0x6E, 0xC1, 0x42, 0xA8, 0x3A,
    # Key 13: Unknown
    0x28, 0x55, 0x48, 0x52, 0x24, 0x72, 0x63, 0x37, 0x14, 0x26, 0x37, 0x50, 0xBE, 0xFE, 0x00, 0x00,
    # Key 14: IMEI NV key
    0x22, 0x63, 0x48, 0x02, 0x24, 0x72, 0x27, 0x37, 0x19, 0x26, 0x37, 0x50, 0xBE, 0xEF, 0xCA, 0xFE,
    # Key 15: AC791L/AC790S OPENMEP (old)
    0x98, 0xE1, 0xC1, 0x93, 0xC3, 0xBF, 0xC3, 0x50, 0x8D, 0xA1, 0x35, 0xFE, 0x50, 0x47, 0xB3, 0xC4,
    # Key 16: AC791/AC790S OPENMEP
    0x61, 0x94, 0xCE, 0xA7, 0xB0, 0xEA, 0x4F, 0x0A, 0x73, 0xC5, 0xC3, 0xA6, 0x5E, 0xEC, 0x1C, 0xE2,
    # Key 17: AC791/AC790S OPENLOCK (old)
    0xC5, 0x50, 0x40, 0xDA, 0x23, 0xE8, 0xF4, 0x4C, 0x29, 0xE9, 0x07, 0xDE, 0x24, 0xE5, 0x2C, 0x1D,
    # Key 18: AC791/AC790S OPENLOCK
    0xF0, 0x14, 0x55, 0x0D, 0x5E, 0xDA, 0x92, 0xB3, 0xA7, 0x6C, 0xCE, 0x84, 0x90, 0xBC, 0x7F, 0xED,
    # Key 19: WP77xx OPENMEP
    0x78, 0x19, 0xC5, 0x6D, 0xC3, 0xD8, 0x25, 0x3E, 0x51, 0x60, 0x8C, 0xA7, 0x32, 0x83, 0x37, 0x9D,
    # Key 20: WP77xx OPENLOCK
    0x12, 0xF0, 0x79, 0x6B, 0x19, 0xC7, 0xF4, 0xEC, 0x50, 0xF3, 0x8C, 0x40, 0x02, 0xC9, 0x43, 0xC8,
    # Key 21: NTGX55 OPENMEP (MR5100)
    0x49, 0x42, 0xFF, 0x76, 0x8A, 0x95, 0xCF, 0x7B, 0xA3, 0x47, 0x5F, 0xF5, 0x8F, 0xD8, 0x45, 0xE4,
    # Key 22: NTGX55 OPENLOCK (MR5100)
    0xF8, 0x1A, 0x3A, 0xCC, 0xAA, 0x2B, 0xA5, 0xE8, 0x8B, 0x53, 0x5A, 0x55, 0xB9, 0x65, 0x57, 0x98,
    # Key 23: NTG9X15A OPENMEP
    0x54, 0xC9, 0xC7, 0xA4, 0x02, 0x1C, 0xB0, 0x11, 0x05, 0x22, 0x39, 0xB7, 0x84, 0xEF, 0x16, 0xCA,
    # Key 24: NTG9X15A OPENLOCK
    0xC7, 0xE6, 0x39, 0xFE, 0x0A, 0xC7, 0xCA, 0x4D, 0x49, 0x8F, 0xD8, 0x55, 0xEB, 0x1A, 0xCD, 0x8A,
    # Key 25: NTGX65 OPENLOCK
    0xF2, 0x4A, 0x9A, 0x2C, 0xDA, 0x3D, 0xA5, 0xE2, 0x6B, 0x56, 0x9A, 0x45, 0x29, 0x25, 0x77, 0x9A,
    # Key 26: NTGX65 OPENADM
    0x46, 0x30, 0x33, 0x43, 0x44, 0x36, 0x42, 0x34, 0x41, 0x32, 0x31, 0x32, 0x30, 0x35, 0x39, 0x37,
    # Key 27: NTGX75 OPENMEP
    0xC8, 0x6D, 0x41, 0x84, 0x8F, 0xA0, 0x73, 0x4B, 0x4B, 0x93, 0x6A, 0x08, 0x41, 0xEA, 0x56, 0x97,
    # Key 28: NTGX75 OPENLOCK
    0xEE, 0xB8, 0x48, 0x7E, 0xB1, 0xA2, 0xA9, 0x18, 0x8E, 0x7B, 0x44, 0xCE, 0xE6, 0x24, 0xCB, 0xF7
])


# ============================================================================
# SIERRA ALGORITHM IMPLEMENTATION
# ============================================================================

class SierraGenerator:
    """
    Sierra Wireless challenge-response generator
    Implements the core encryption algorithm used for carrier unlock
    """

    def __init__(self):
        self.tbl = bytearray([0] * 0x100)
        self.rtbl = bytearray([0] * 0x14)
        self.devicegeneration = None

    def SierraPreInit(self, counter: int, key: bytearray, keylen: int,
                      challengelen: int, mcount: int) -> List[int]:
        """Pre-initialization step for key schedule"""
        if counter != 0:
            tmp2 = 0
            i = 1
            while i < counter:
                i = 2 * i + 1
            while True:
                tmp = mcount
                mcount = tmp + 1
                challengelen = (key[tmp & 0xFF] +
                                self.tbl[(challengelen & 0xFF)]) & 0xFF
                if mcount >= keylen:
                    mcount = 0
                    challengelen = ((challengelen & 0xFF) + keylen) & 0xFF
                tmp2 = tmp2 + 1
                tmp3 = ((challengelen & 0xFF) & i) & 0xFF
                if tmp2 >= 0xB:
                    tmp3 = counter % tmp3
                if tmp3 <= counter:
                    break
            counter = tmp3 & 0xFF
        return [counter, challengelen, mcount]

    def SierraInit(self, key: bytearray, keylen: int) -> Tuple[int, int]:
        """Initialize encryption tables with key"""
        if keylen == 0 or keylen > 0x20:
            return [0, keylen]

        # Initialize table with sequential values
        self.tbl = bytearray([(i & 0xFF) for i in range(0x100)])
        mcount = 0
        cl = keylen & 0xffffff00

        # Key schedule permutation
        i = 0xFF
        while i > -1:
            t, cl, mcount = self.SierraPreInit(i, key, keylen, cl, mcount)
            m = self.tbl[i]
            self.tbl[i] = self.tbl[(t & 0xff)]
            self.tbl[(t & 0xFF)] = m
            i = i - 1

        # Initialize result table
        init = PRODTABLE[self.devicegeneration]["init"]
        self.rtbl[0] = self.tbl[init[0]
                                ] if init[0] != 0 else self.tbl[(cl & 0xFF)]
        self.rtbl[1] = self.tbl[init[1]
                                ] if init[1] != 0 else self.tbl[(cl & 0xFF)]
        self.rtbl[2] = self.tbl[init[2]
                                ] if init[2] != 0 else self.tbl[(cl & 0xFF)]
        self.rtbl[3] = self.tbl[init[3]
                                ] if init[3] != 0 else self.tbl[(cl & 0xFF)]
        self.rtbl[4] = self.tbl[init[4]
                                ] if init[4] != 0 else self.tbl[(cl & 0xFF)]

        return [1, keylen]

    def SierraAlgo(self, challenge: int, a: int = 0, b: int = 1, c: int = 2,
                   d: int = 3, e: int = 4, ret: int = 3, ret2: int = 1,
                   flag: int = 1) -> int:
        """
        Core Sierra algorithm - performs table lookups and XOR operations
        Parameters a-e control which table entries are used
        """
        v6 = self.rtbl[e]
        v0 = (v6 + 1) & 0xFF
        self.rtbl[e] = v0
        self.rtbl[c] = (self.tbl[v6 + flag & 0xFF] + self.rtbl[c]) & 0xFF
        v4 = self.rtbl[c] & 0xFF
        v2 = self.rtbl[b] & 0xFF
        v1 = self.tbl[(v2 & 0xFF)]
        self.tbl[(v2 & 0xFF)] = self.tbl[(v4 & 0xFF)]
        v5 = self.rtbl[d] & 0xFF
        self.tbl[(v4 & 0xFF)] = self.tbl[(v5 & 0xFF)]
        self.tbl[(v5 & 0xFF)] = self.tbl[(v0 & 0xFF)]
        self.tbl[v0] = v1 & 0xFF

        u = self.tbl[(self.tbl[(
            self.tbl[((self.rtbl[a] + self.tbl[(v1 & 0xFF)]) & 0xFF)] +
            self.tbl[(v5 & 0xFF)] + self.tbl[(v2 & 0xFF)] & 0xff)] & 0xFF)]
        v = self.tbl[((self.tbl[(v4 & 0xFF)] + v1) & 0xFF)]

        self.rtbl[ret] = u ^ v ^ challenge
        self.rtbl[a] = (self.tbl[(v1 & 0xFF)] + self.rtbl[a]) & 0xFF
        self.rtbl[ret2] = challenge & 0xFF

        return self.rtbl[ret] & 0xFF

    def SierraFinish(self) -> int:
        """Clean up tables after key generation"""
        self.tbl = bytearray([0] * 0x100)
        self.rtbl[0] = 0
        self.rtbl[1] = 0
        self.rtbl[2] = 0
        self.rtbl[3] = 0
        self.rtbl[4] = 0
        return 1

    def SierraKeygen(self, challenge: bytearray, key: bytearray,
                     challengelen: int, keylen: int) -> bytearray:
        """Generate response for given challenge"""
        resultbuffer = bytearray([0] * (0x100 + 1))
        ret, keylen = self.SierraInit(key, keylen)

        if ret:
            for i in range(challengelen):
                # Execute device-specific algorithm
                exec(PRODTABLE[self.devicegeneration]["run"])
            self.SierraFinish()

        return resultbuffer

    def run(self, devicegeneration: str, challenge: str, unlock_type: int) -> str:
        """
        Generate unlock response

        Args:
            devicegeneration: Device generation (e.g., "MDM9x40", "SDX20")
            challenge: Hex challenge from modem (e.g., "BE96CBBEE0829BCA")
            unlock_type: 0=openlock, 1=openmep, 2=opencnd

        Returns:
            Hex response string (e.g., "1033773720F6EE66")
        """
        challenge_bytes = bytearray(unhexlify(challenge))
        self.devicegeneration = devicegeneration

        if devicegeneration not in PRODTABLE:
            raise ValueError(
                f"Unsupported device generation: {devicegeneration}")

        # Get algorithm parameters
        mepid = PRODTABLE[devicegeneration]["openmep"]
        cndid = PRODTABLE[devicegeneration]["opencnd"]
        lockid = PRODTABLE[devicegeneration]["openlock"]
        clen = PRODTABLE[devicegeneration]["clen"]

        # Pad challenge if needed
        if len(challenge_bytes) < clen:
            challenge_bytes = bytearray(
                [0] * (clen - len(challenge_bytes))) + challenge_bytes

        challengelen = len(challenge_bytes)

        # Select key based on unlock type
        if unlock_type == 0:  # lockkey
            idf = lockid
        elif unlock_type == 1:  # mepkey
            idf = mepid
        elif unlock_type == 2:  # cndkey
            idf = cndid
        else:
            raise ValueError(f"Invalid unlock type: {unlock_type}")

        # Extract key from table
        key = KEYTABLE[idf * 16:(idf * 16) + 16]

        # Generate response
        resp = self.SierraKeygen(
            challenge=challenge_bytes,
            key=key,
            challengelen=challengelen,
            keylen=16
        )[:challengelen]

        return hexlify(resp).decode('utf-8').upper()

    def selftest(self) -> Dict[str, bool]:
        """
        Run self-test with known challenge-response pairs
        Returns dict of {devicegeneration: passed}
        """
        test_table = [
            {"challenge": "8101A18AB3C3E66A", "devicegeneration": "MDM9x15",
                "response": "D1E128FCA8A963ED"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x40",
                "response": "1033773720F6EE66"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x30",
                "response": "1E02CE6A98B7DD2A"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x50",
                "response": "32AB617DB4B1C205"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM8200",
                "response": "EE702212D9C12FAB"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9200",
                "response": "EEDBF8BFF8DAE346"},
            {"challenge": "20E253156762DACE", "devicegeneration": "SDX55",
                "response": "03940D7067145323"},
            {"challenge": "4B1FEF9FD43C6DAA", "devicegeneration": "SDX65",
                "response": "1253C1B1E447B697"}
        ]

        results = {}
        for test in test_table:
            challenge = test["challenge"]
            devicegeneration = test["devicegeneration"]
            expected_response = test["response"]

            try:
                actual_response = self.run(
                    devicegeneration, challenge, 0)  # openlock
                results[devicegeneration] = (
                    actual_response == expected_response)
            except Exception as e:
                results[devicegeneration] = False

        return results


# ============================================================================
# MIFI ADAPTER FUNCTIONS
# ============================================================================

def detect_device_generation(firmware: str, model: str) -> Optional[str]:
    """
    Detect device generation from firmware string

    Args:
        firmware: Firmware version string (e.g., "SDx20ALP-1.22.11")
        model: Model name (e.g., "MIFI8800L")

    Returns:
        Device generation string or None

    Examples:
        >>> detect_device_generation("SDx20ALP-1.22.11", "MIFI8800L")
        'SDX20'
        >>> detect_device_generation("NTGX55_10.25.15.02", "MR5100")
        'SDX55'
    """
    firmware_upper = firmware.upper()

    # Check firmware string patterns
    if "SDX20" in firmware_upper or "SDx20" in firmware:
        return "SDX20"
    elif "X55" in firmware_upper or "9X40C" in firmware_upper:
        return "SDX55"
    elif "X65" in firmware_upper:
        return "SDX65"
    elif "9X50" in firmware_upper:
        return "MDM9x50"
    elif "9X40" in firmware_upper:
        return "MDM9x40"
    elif "9X30" in firmware_upper or "9X35" in firmware_upper:
        return "MDM9x30"
    elif "9X15" in firmware_upper:
        return "MDM9x15"

    # Check model name
    model_upper = model.upper()
    for generation, models in INFOTABLE.items():
        if any(m.upper() in model_upper for m in models):
            return generation

    return None


def calculate_unlock_response(challenge: str, devicegeneration: str = "SDX20",
                              unlock_type: int = 0) -> str:
    """
    Calculate unlock response for given challenge

    Args:
        challenge: Hex challenge from modem (e.g., "BE96CBBEE0829BCA")
        devicegeneration: Device generation (default: "SDX20" for MiFi 8800L)
        unlock_type: 0=openlock (carrier), 1=openmep (SIM), 2=opencnd

    Returns:
        Hex response string

    Raises:
        ValueError: If device generation not supported or challenge invalid

    WARNING: This function does NOT verify if the algorithm is correct for
    Qualcomm SDX20 (MiFi 8800L). The algorithm may differ from Sierra devices.
    Always test with non-critical device first!

    Example:
        >>> calculate_unlock_response("BE96CBBEE0829BCA", "MDM9x40", 0)
        '1033773720F6EE66'
    """
    # Validate challenge
    try:
        challenge_bytes = unhexlify(challenge)
    except Exception as e:
        raise ValueError(f"Invalid hex challenge: {e}")

    if len(challenge_bytes) > 8:
        raise ValueError(
            f"Challenge too long: {len(challenge_bytes)} bytes (max 8)")

    # Generate response
    generator = SierraGenerator()
    return generator.run(devicegeneration, challenge, unlock_type)


def run_selftest() -> Tuple[bool, Dict[str, bool]]:
    """
    Run algorithm self-test with known challenge-response pairs

    Returns:
        (all_passed, results_dict)

    Example:
        >>> passed, results = run_selftest()
        >>> print(f"All tests passed: {passed}")
        >>> for device, result in results.items():
        ...     print(f"{device}: {'PASSED' if result else 'FAILED'}")
    """
    generator = SierraGenerator()
    results = generator.selftest()
    all_passed = all(results.values())
    return all_passed, results


# ============================================================================
# MiFi-SPECIFIC FUNCTIONS
# ============================================================================

def get_supported_devices() -> Dict[str, List[str]]:
    """Return dict of device generations and their supported models"""
    return INFOTABLE.copy()


def get_algorithm_info(devicegeneration: str) -> Optional[Dict]:
    """Get algorithm parameters for device generation"""
    return PRODTABLE.get(devicegeneration)


def is_mifi_device(model: str) -> bool:
    """Check if model is an Inseego MiFi device"""
    model_upper = model.upper()
    return any(x in model_upper for x in ["MIFI", "8800L", "M2000", "M2100"])


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    import sys

    print("Sierra Wireless Unlock Algorithm Adapter")
    print("=" * 60)
    print()

    # Run self-test
    print("Running algorithm self-test...")
    all_passed, results = run_selftest()
    print()

    for device, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {device:20s} {status}")

    print()
    print(
        f"Overall: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
    print()

    # Show MiFi info
    print("MiFi 8800L Information:")
    print("-" * 60)
    print(f"  Chipset: Qualcomm SDX20 (Alpine)")
    print(
        f"  Algorithm: {'SDX20' if 'SDX20' in PRODTABLE else 'UNKNOWN (trying MDM9x40)'}")
    print(f"  Key Index: {PRODTABLE.get('SDX20', {}).get('openlock', 'N/A')}")
    print(
        f"  Challenge Length: {PRODTABLE.get('SDX20', {}).get('clen', 'N/A')} bytes")
    print()
    print("⚠️  WARNING: SDX20 algorithm compatibility is UNCERTAIN!")
    print("   Qualcomm SDX20 may use different algorithm than Sierra devices.")
    print("   Test on non-critical device first. Wrong NCK may permanently lock device!")
    print()

    sys.exit(0 if all_passed else 1)
