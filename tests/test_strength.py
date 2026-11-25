from core.generator import generate
from core.strength import LEVELS, check, common_passwords, is_acceptable_master, user_inputs_from_entry


def test_common_list_is_loaded():
    words = common_passwords()
    assert "password" in words and "123456" in words


def test_known_samples():
    assert check("password").level == "Very Weak"
    assert check("P@ssw0rd").level in ("Very Weak", "Weak")
    assert check("xK9#mQ2$vL7!pR4@wZ8^").level == "Very Strong"  # 20 random characters


def test_generated_passwords_are_strong():
    for _ in range(50):
        assert check(generate(20)).level == "Very Strong"


def test_patterns_are_penalised():
    base = check("Kj8#Lm2$Qr").entropy_bits
    assert check("Kj8#Lm2$Qrabcdef").entropy_bits < check("Kj8#Lm2$QrXpVbNw").entropy_bits  # sequence
    assert check("Kj8#Lm2$Qraaaaaa").entropy_bits < check("Kj8#Lm2$QrXpVbNw").entropy_bits  # repeat
    assert check("Kj8#Lm2$Qrqwerty").entropy_bits < check("Kj8#Lm2$QrXpVbNw").entropy_bits  # keyboard walk
    assert check("Kj8#Lm2$Qr1998").entropy_bits < check("Kj8#Lm2$Qr7k3x").entropy_bits  # year
    assert base > 0


def test_feedback_mentions_the_problem():
    assert any("sequence" in tip.lower() for tip in check("Zebra!fghijk9").feedback)
    assert any("keyboard" in tip.lower() for tip in check("Tq!qwerty77X").feedback)
    assert any("year" in tip.lower() for tip in check("Tiger#Moon1999").feedback)
    assert 1 <= len(check("xK9#mQ2$vL7!pR4@wZ8^").feedback) <= 3


def test_username_and_site_name_penalised():
    inputs = user_inputs_from_entry("Amazon", "https://www.amazon.com", "rahul.k@example.com")
    assert "amazon" in [i.lower() for i in inputs] and "rahul.k" in inputs
    with_site = check("Amazon#7Vx2q", inputs)
    assert with_site.entropy_bits < check("Amazon#7Vx2q").entropy_bits
    assert any("username" in tip.lower() for tip in with_site.feedback)


def test_levels_and_score_range():
    for pw in ("", "a", "abc123", "Summer2024!", "correct horse battery staple", generate(64)):
        result = check(pw)
        assert result.level in LEVELS
        assert 0 <= result.score <= 100


def test_master_password_rule():
    assert is_acceptable_master("Blue-Kettle-92-Orbit!x")[0]
    assert is_acceptable_master("kdjfhqpwmzxa")[0]  # 12 random lowercase: Medium and 12+ long
    assert not is_acceptable_master("password123")[0]
    assert not is_acceptable_master("Ab1!xyz")[0]
