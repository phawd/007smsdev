"""
Safety helpers for ZeroSMS CLI and Python tools.
Provides runtime confirmation for dangerous operations that modify NV items,
unlock carriers, or write EFS entries.
"""
import os
from typing import Optional


def confirm_danger(
    allow_flag: bool = False,
    prompt: Optional[str] = None,
    force_yes: bool = False,
) -> bool:
    """
    Require explicit typed confirmation for dangerous operations.

    - If force_yes=True, return True (useful for tests).
        - If allow_flag is True, require the user to type 'DO IT' interactively
            (or check env_var).
    - If env_var is set to '1', skip interactive prompt.

    Returns True if operation is confirmed, otherwise False.
    """
    if force_yes:
        return True

    if os.environ.get("ZEROSMS_DANGER_DO_IT", "0") == "1":
        return True

    if not allow_flag:
        # Not allowed here: the caller must explicitly pass
        # allow_flag=True to allow dangerous operations
        return False

    if prompt is None:
        prompt = (
            "This operation can permanently change device state\n"
            "(NV writes, unlock, factory reset).\nType 'DO IT' to proceed: "
        )

    try:
        resp = input(prompt).strip()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        return False

    return resp == "DO IT"
