import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from zerosms_safety import confirm_danger


def test_force_yes_returns_true():
    assert confirm_danger(force_yes=True) is True


def test_env_var_allows():
    os.environ['ZEROSMS_DANGER_DO_IT'] = '1'
    try:
        assert confirm_danger(allow_flag=False) is True
    finally:
        del os.environ['ZEROSMS_DANGER_DO_IT']


def test_allow_flag_without_env_and_no_prompt():
    # Without force_yes and no env var, allow_flag=False should return False
    assert not confirm_danger(allow_flag=False)
