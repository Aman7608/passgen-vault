import string

import pytest

from core.generator import AMBIGUOUS, SYMBOL_CHARS, GeneratorError, generate


def test_length_bounds():
    assert len(generate(8)) == 8
    assert len(generate(64)) == 64
    for bad in (7, 65, 0, -1):
        with pytest.raises(GeneratorError):
            generate(bad)


def test_all_selected_classes_present():
    for _ in range(300):
        pw = generate(8)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOL_CHARS for c in pw)


def test_only_selected_classes_used():
    for _ in range(100):
        pw = generate(20, upper=False, lower=False, digits=True, symbols=False)
        assert pw.isdigit()
        pw = generate(20, upper=False, lower=True, digits=False, symbols=False)
        assert pw.islower() and pw.isalpha()


def test_ambiguous_characters_excluded():
    for _ in range(300):
        assert not set(generate(64, exclude_ambiguous=True)) & AMBIGUOUS


def test_no_set_selected_is_an_error():
    with pytest.raises(GeneratorError):
        generate(16, upper=False, lower=False, digits=False, symbols=False)


def test_results_are_different():
    assert len({generate(16) for _ in range(200)}) == 200
