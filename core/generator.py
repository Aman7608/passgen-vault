"""Random password generator. Uses the secrets module only, never random."""

import secrets
import string

MIN_LENGTH = 8
MAX_LENGTH = 64
AMBIGUOUS = set("O0Il1")
SYMBOL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/~"

_rng = secrets.SystemRandom()


class GeneratorError(ValueError):
    pass


def generate(length=16, upper=True, lower=True, digits=True, symbols=True, exclude_ambiguous=False) -> str:
    if not isinstance(length, int) or not MIN_LENGTH <= length <= MAX_LENGTH:
        raise GeneratorError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    sets = []
    if upper:
        sets.append(string.ascii_uppercase)
    if lower:
        sets.append(string.ascii_lowercase)
    if digits:
        sets.append(string.digits)
    if symbols:
        sets.append(SYMBOL_CHARS)
    if not sets:
        raise GeneratorError("Pick at least one character type.")
    if exclude_ambiguous:
        sets = ["".join(c for c in chars if c not in AMBIGUOUS) for chars in sets]

    # One character from every chosen set first, so each type is guaranteed...
    chars = [secrets.choice(group) for group in sets]
    # ...then fill the rest from all chosen sets together, and shuffle.
    everything = "".join(sets)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    _rng.shuffle(chars)
    return "".join(chars)
