"""Logging setup. The rule: log events, never values.
Messages say things like "Entry added (id=4)", never names, usernames or passwords."""

import logging
from logging.handlers import RotatingFileHandler


def setup_logging(log_file, level=logging.INFO):
    handler = RotatingFileHandler(log_file, maxBytes=512 * 1024, backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
    # Matplotlib and PIL are chatty at debug level and have nothing useful for us.
    for noisy in ("matplotlib", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return handler
