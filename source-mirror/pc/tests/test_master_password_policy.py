import inspect

from core.master_password_policy import PasswordRisk, assess_master_password
from ui import dialogs


COMMON = frozenset(("password", "summer", "123456"))


def _assess(password: str):
    return assess_master_password(password, common_password_check=COMMON.__contains__)


def test_six_digit_and_short_random_passwords_are_blocked():
    assert _assess("123456").risk is PasswordRisk.BLOCKED
    assert _assess("aB3$zQ").risk is PasswordRisk.BLOCKED


def test_common_password_transformations_are_blocked_without_substring_matching():
    assert _assess("Password1!").risk is PasswordRisk.BLOCKED
    assert _assess("Summer2026!").risk is PasswordRisk.BLOCKED
    assert _assess("summer-orbit-cobalt-lantern-meadow").risk is PasswordRisk.STRONG


def test_weak_password_needs_an_explicit_standard_mode_override():
    result = _assess("aB3$zQ7!")

    assert result.risk is PasswordRisk.WEAK
    assert not result.permits(high_security_mode=True, weak_password_confirmed=True)
    assert not result.permits(high_security_mode=False, weak_password_confirmed=False)
    assert result.permits(high_security_mode=False, weak_password_confirmed=True)


def test_random_passwords_and_long_passphrases_meet_the_recommendation():
    assert _assess("V7!qL2#nP9@x").risk is PasswordRisk.STRONG
    assert _assess("orbit cedar cobalt lantern meadow").risk is PasswordRisk.STRONG


def test_repeated_words_and_repeated_character_pseudo_passphrases_are_blocked():
    assert _assess("alpha alpha alpha alpha alpha").risk is PasswordRisk.BLOCKED
    assert _assess("aaaa bbbb cccc dddd eeee").risk is PasswordRisk.BLOCKED


def test_desktop_create_change_and_recovery_flows_use_the_shared_policy():
    for dialog_type in (
        dialogs.AddUserDialog,
        dialogs.ChangePasswordDialog,
        dialogs._RecoveryResetPasswordDialog,
    ):
        source = inspect.getsource(dialog_type)
        assert "_master_password_policy_allows" in source
        assert "high_security" in source
