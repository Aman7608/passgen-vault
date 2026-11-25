"""Clipboard copy with auto-clear.

This file doesn't touch any GUI. The GUI passes in small functions to read and
write the clipboard and to schedule a timer, so the logic can be tested with fakes.
"""

import hashlib
import logging

log = logging.getLogger(__name__)


def _fingerprint(text: str) -> bytes:
    # Keep a hash of what we copied, not the password itself.
    return hashlib.sha256(text.encode("utf-8")).digest()


class ClipboardGuard:
    def __init__(self, get_text, set_text, schedule, cancel, clear_after_seconds=20):
        """
        get_text()            -> current clipboard text ("" if empty or not text)
        set_text(text)        -> put text on the clipboard
        schedule(ms, func)    -> run func later, return a handle
        cancel(handle)        -> cancel a scheduled run
        """
        self._get = get_text
        self._set = set_text
        self._schedule = schedule
        self._cancel = cancel
        self.clear_after_seconds = clear_after_seconds
        self._copied = None
        self._timer = None

    def copy(self, text: str, secret=True):
        self._cancel_timer()
        self._set(text)
        if secret and self.clear_after_seconds > 0:
            self._copied = _fingerprint(text)
            self._timer = self._schedule(int(self.clear_after_seconds * 1000), self._auto_clear)
        else:
            self._copied = None

    def _auto_clear(self):
        self._timer = None
        self.clear_if_ours()

    def clear_if_ours(self) -> bool:
        """Clear the clipboard only if it still holds what we copied.
        If the user copied something else since then, leave it alone."""
        self._cancel_timer()
        if self._copied is None:
            return False
        ours = False
        try:
            ours = _fingerprint(self._get() or "") == self._copied
        except Exception:
            ours = False
        if ours:
            self._set("")
            log.info("Clipboard cleared")
        self._copied = None
        return ours

    @property
    def pending(self) -> bool:
        return self._copied is not None

    def _cancel_timer(self):
        if self._timer is not None:
            try:
                self._cancel(self._timer)
            except Exception:
                pass
            self._timer = None
