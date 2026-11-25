# Assets

## common_passwords.txt

Used by `core/strength.py`. Any password on this list is rated Very Weak, and words from it (5+ letters) hidden inside a longer password lower the score.

- **What it is:** the top 10,000 most common passwords from real breach data.
- **Source:** SecLists by Daniel Miessler, `Passwords/Common-Credentials/10k-most-common.txt`
  (https://github.com/danielmiessler/SecLists, commit `fcde914`)
- **License:** MIT, Copyright (c) 2018 Daniel Miessler

Format: one password per line. Lines starting with `#` are comments (the credit at the top). The checker lower-cases everything when it loads the file.

### MIT License (SecLists)

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
