"""Offline password strength checker.

How the score works:
1. Start with an entropy estimate: length x log2(size of the character pool),
   where the pool is made from the character classes used (a-z, A-Z, 0-9, symbols).
2. Find weak patterns: common passwords (also with l33t swaps like @ -> a),
   sequences (abc, 123), repeats (aaa), keyboard walks (qwerty), years and dates,
   and the entry's own username or site name.
3. Characters inside a weak pattern stop counting at full value. Each pattern
   is charged a small fixed number of bits instead (roughly how many guesses
   an attacker needs to try that pattern).
4. The final estimate in bits picks the level, and the score is the bits capped at 100.
"""

import math
import re
import string
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlparse

from core.config import COMMON_PASSWORDS_FILE

LEVELS = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
# Upper bits limit for each level (Very Strong has no limit).
_LEVEL_LIMITS = [(28, "Very Weak"), (40, "Weak"), (60, "Medium"), (80, "Strong")]

SYMBOLS = string.punctuation  # 32 symbols
_KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "1qaz2wsx"]
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t", "+": "t", "|": "l", "8": "b", "9": "g"})
_LEET_ONE_AS_L = str.maketrans({"1": "l"})

# How many bits each kind of pattern is worth (about log2 of the guesses needed).
_COST_DICTIONARY = 12
_COST_USER_INFO = 4
_COST_KEYBOARD = 6
_COST_SEQUENCE = 5
_COST_REPEAT = 4
_COST_YEAR = 7
_COST_DATE = 12


@dataclass
class StrengthResult:
    score: int  # 0-100
    level: str
    entropy_bits: float
    feedback: list = field(default_factory=list)

    @property
    def level_index(self) -> int:
        return LEVELS.index(self.level)


@lru_cache(maxsize=1)
def common_passwords() -> frozenset:
    """Load the bundled common-password list once. Lines starting with # are comments."""
    words = set()
    try:
        with open(COMMON_PASSWORDS_FILE, encoding="utf-8") as handle:
            for line in handle:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.add(word)
    except FileNotFoundError:
        pass  # the checker still works, just without the dictionary penalty
    return frozenset(words)


def pool_size(password: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in SYMBOLS or c == " " for c in password):
        pool += 33
    if any(ord(c) > 127 for c in password):
        pool += 100  # rough guess for letters outside ASCII
    return pool


def user_inputs_from_entry(name="", url="", username="") -> list:
    """Pick the words from an entry that shouldn't appear in its password."""
    words = [name, username]
    if username and "@" in username:
        words.append(username.split("@")[0])
    if url:
        host = urlparse(url if "://" in url else "https://" + url).hostname or ""
        parts = [p for p in host.split(".") if p not in ("www", "com", "org", "net", "in", "co", "io")]
        words.extend(parts)
    return [w for w in words if w]


def _find_sequences(lower: str):
    """Runs of 3+ characters going up or down by one, like abc, 123, 987."""
    found, start = [], 0
    while start < len(lower) - 2:
        step = ord(lower[start + 1]) - ord(lower[start])
        end = start + 1
        if step in (1, -1) and (lower[start].isalnum()):
            while end < len(lower) and ord(lower[end]) - ord(lower[end - 1]) == step and lower[end].isalnum():
                end += 1
        if end - start >= 3:
            found.append((start, end))
            start = end
        else:
            start += 1
    return found


def _find_repeats(text: str):
    """The same character 3+ times in a row (aaa), or a repeated chunk (abcabc)."""
    found = [(m.start(), m.end()) for m in re.finditer(r"(.)\1{2,}", text)]
    found += [(m.start(), m.end()) for m in re.finditer(r"(.{2,})\1+", text)]
    return found


def _find_keyboard(lower: str):
    found = []
    for row in _KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            for size in range(len(line), 3, -1):  # 4 or more keys in a row
                for i in range(len(line) - size + 1):
                    chunk = line[i:i + size]
                    pos = lower.find(chunk)
                    while pos != -1:
                        found.append((pos, pos + size))
                        pos = lower.find(chunk, pos + 1)
    return found


def _find_dictionary(variants: list, words: frozenset):
    """Common passwords (5+ letters) hidden inside the password, also after l33t swaps."""
    found = []
    for text in variants:
        for size in range(min(len(text), 20), 4, -1):
            for i in range(len(text) - size + 1):
                if text[i:i + size] in words:
                    found.append((i, i + size))
    return found


def _find_dates(text: str):
    years = [(m.start(), m.end()) for m in re.finditer(r"(?<!\d)(19\d\d|20\d\d)(?!\d)", text)]
    dates = [(m.start(), m.end()) for m in re.finditer(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}|(?<!\d)\d{8}(?!\d)|(?<!\d)\d{6}(?!\d)", text)]
    return years, dates


def check(password: str, user_inputs=()) -> StrengthResult:
    if not password:
        return StrengthResult(0, "Very Weak", 0.0, ["Type a password to check it."])

    lower = password.lower()
    leet = lower.translate(_LEET)
    leet_l = lower.translate(_LEET_ONE_AS_L).translate(_LEET)
    words = common_passwords()
    bits_per_char = math.log2(max(pool_size(password), 2))

    weak = [False] * len(password)
    extra_bits = 0.0
    problems = []

    def charge(spans, cost, message):
        nonlocal extra_bits
        hit = False
        for start, end in sorted(spans, key=lambda s: s[0] - s[1]):  # longest first
            if not all(weak[start:end]):
                for i in range(start, end):
                    weak[i] = True
                extra_bits += cost
                hit = True
        if hit and message not in problems:
            problems.append(message)

    # 1. The whole password is a common one (also after l33t swaps).
    is_common = lower in words or leet in words or leet_l in words
    if is_common:
        problems.append("This is one of the most common passwords. Pick something unique.")

    # 2. Username or site name inside the password.
    user_spans = []
    for word in user_inputs:
        word = str(word).lower().strip()
        if len(word) >= 3:
            for text in (lower, leet):
                pos = text.find(word)
                while pos != -1:
                    user_spans.append((pos, pos + len(word)))
                    pos = text.find(word, pos + 1)
    charge(user_spans, _COST_USER_INFO, "Don't put your username or the site name in the password.")

    # 3. Keyboard walks (checked before the word list, which also has "qwerty" in it).
    charge(_find_keyboard(lower), _COST_KEYBOARD, "Avoid keyboard patterns like qwerty or asdf.")

    # 4. Common words hidden inside.
    charge(_find_dictionary([lower, leet, leet_l], words), _COST_DICTIONARY,
           "Avoid common words and passwords, even with symbols swapped in.")

    # 5. Years and dates, sequences, repeats.
    years, dates = _find_dates(password)
    charge(dates, _COST_DATE, "Avoid dates. They are easy to guess.")
    charge(years, _COST_YEAR, "Avoid years like 1999 or 2024.")
    charge(_find_sequences(lower), _COST_SEQUENCE, "Avoid sequences like abc or 123.")
    charge(_find_repeats(lower), _COST_REPEAT, "Avoid repeated characters like aaa.")

    strong_chars = weak.count(False)
    entropy = strong_chars * bits_per_char + extra_bits
    if is_common:
        entropy = min(entropy, 8.0)
    if len(password) < 8:
        entropy = min(entropy, 39.0)  # never above Weak

    level = "Very Strong"
    for limit, name in _LEVEL_LIMITS:
        if entropy < limit:
            level = name
            break

    tips = list(problems)
    if is_common:  # the "most common password" tip already says it
        tips = [t for t in tips if not t.startswith("Avoid common words")]
    if len(password) < 12:
        tips.append("Use at least 12 characters. Length helps the most.")
    missing = []
    if not any(c.isupper() for c in password):
        missing.append("uppercase letters")
    if not any(c.isdigit() for c in password):
        missing.append("numbers")
    if not any(c in SYMBOLS for c in password):
        missing.append("symbols")
    if missing and LEVELS.index(level) < 3:
        tips.append("Add " + ", ".join(missing) + ".")
    if not tips:
        tips.append("Nice, this is a strong password." if LEVELS.index(level) >= 3 else "Make it longer to make it stronger.")

    return StrengthResult(min(100, round(entropy)), level, round(entropy, 1), tips[:3])


def is_acceptable_master(password: str) -> tuple[bool, StrengthResult]:
    """Master password rule: a Strong rating, or 12+ characters with at least a Medium rating."""
    result = check(password)
    ok = result.level_index >= LEVELS.index("Strong") or (
        len(password) >= 12 and result.level_index >= LEVELS.index("Medium")
    )
    return ok, result
