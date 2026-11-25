"""Start PassGen Vault."""

import logging
import sys

from core import config
from core.logging_setup import setup_logging


def main():
    setup_logging(config.log_path())
    log = logging.getLogger("passgen")
    log.info("App started")
    try:
        from gui.app import PassGenApp
        app = PassGenApp()
    except Exception as err:  # e.g. the vault file is from a newer version
        log.error("Could not start: %s", type(err).__name__)
        from tkinter import Tk, messagebox
        root = Tk()
        root.withdraw()
        messagebox.showerror("PassGen Vault", f"PassGen Vault could not start.\n\n{err}\n\nLog file: {config.log_path()}")
        root.destroy()
        sys.exit(1)
    app.mainloop()
    log.info("App closed")


if __name__ == "__main__":
    main()
