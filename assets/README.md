# Assets

## common_passwords.txt

Used by `core/strength.py`. Any password on this list is rated Very Weak, and words from it hidden inside a longer password lower the score.

Format: one password per line, lower case. Lines starting with `#` are comments.

The current file is a short starter list (about 300 of the most common passwords that show up in public breach lists). It is meant to be replaced by the top 10,000 list from SecLists:

- Source: SecLists by Daniel Miessler, `Passwords/Common-Credentials/10k-most-common.txt`
  (https://github.com/danielmiessler/SecLists)
- License: MIT

To swap it in, download that file and save it as `assets/common_passwords.txt`. The code needs no changes.
