"""Main window: switches between the login screen and the app, handles navigation,
auto-lock, the clipboard and friendly error messages."""

import logging
import time
import tkinter as tk
import traceback
from pathlib import Path

import customtkinter as ctk

from core import backup, config
from core.auth import AuthError, AuthManager
from core.clipboard import ClipboardGuard
from core.crypto import DecryptionError
from core.database import Database
from core.settings import load_settings
from core.vault_manager import VaultManager
from gui import theme
from gui.dashboard import DashboardPage
from gui.generator import GeneratorPage
from gui.login import LoginView
from gui.settings import SettingsPage
from gui.vault import EntryForm, VaultPage

log = logging.getLogger(__name__)

PAGES = [("Dashboard", DashboardPage), ("Vault", VaultPage), ("Generator", GeneratorPage), ("Settings", SettingsPage)]


class MainView(ctk.CTkFrame):
    """Sidebar + page area, shown only while the vault is unlocked."""

    def __init__(self, master, app):
        super().__init__(master, fg_color=theme.BG)
        self.app = app
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, fg_color=theme.SIDEBAR, corner_radius=0, width=220)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar.grid_propagate(False)
        theme.label(sidebar, "PassGen", 22, "bold", theme.ACCENT).pack(padx=24, pady=(28, 0), anchor="w")
        theme.label(sidebar, "VAULT", 12, "bold", theme.MUTED).pack(padx=24, pady=(0, 28), anchor="w")

        self.nav_buttons = {}
        for name, _cls in PAGES:
            btn = ctk.CTkButton(sidebar, text=f"   {name}", anchor="w", height=42, corner_radius=8,
                                font=theme.font(14), fg_color="transparent", hover_color=theme.NEUTRAL_BTN,
                                text_color=theme.TEXT, command=lambda n=name: self.show(n))
            btn.pack(fill="x", padx=14, pady=3)
            self.nav_buttons[name] = btn
        theme.button(sidebar, "Lock vault", lambda: app.lock(), kind="danger", height=40).pack(
            side="bottom", fill="x", padx=14, pady=24)
        self.lock_hint = theme.label(sidebar, "", 11, color=theme.MUTED, wraplength=180, justify="left")
        self.lock_hint.pack(side="bottom", padx=24, anchor="w")

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=1, sticky="nsew", padx=28, pady=(24, 10))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)
        self.status = theme.label(self, "", 12, color=theme.ACCENT, anchor="w")
        self.status.grid(row=1, column=1, sticky="ew", padx=30, pady=(0, 12))

        self.pages = {}
        for name, cls in PAGES:
            page = cls(content, app)
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_remove()
            self.pages[name] = page
        self.current = None
        self.update_lock_hint()

    def update_lock_hint(self):
        minutes = self.app.settings["auto_lock_seconds"] // 60
        self.lock_hint.configure(text=f"Auto-locks after {minutes} min of inactivity")

    def show(self, name):
        if self.current:
            self.pages[self.current].grid_remove()
            self.nav_buttons[self.current].configure(fg_color="transparent", text_color=theme.TEXT)
        self.current = name
        self.pages[name].grid()
        self.nav_buttons[name].configure(fg_color=theme.ACCENT_DARK, text_color=theme.ACCENT)
        self.pages[name].on_show()

    def clear(self):
        for page in self.pages.values():
            if hasattr(page, "clear"):
                page.clear()


class PassGenApp(ctk.CTk):
    def __init__(self, vault_file=None):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__()
        self.title(config.APP_TITLE)
        self.configure(fg_color=theme.BG)
        self.geometry("1240x780")
        self.minsize(1100, 700)

        self.vault_file = Path(vault_file) if vault_file else config.vault_path()
        self._open_db()
        self.vault = None
        self.view = None
        self.active_form = None
        self.generator_options = {"length": 20, "upper": True, "lower": True, "digits": True,
                                  "symbols": True, "exclude_ambiguous": False}
        self._flash_job = None

        self.clipboard = ClipboardGuard(self._clipboard_get, self._clipboard_set, self.after, self.after_cancel,
                                        self.settings["clipboard_clear_seconds"])
        # Any key press or mouse action anywhere in the app counts as activity.
        self.last_activity = time.monotonic()
        for sequence in ("<KeyPress>", "<ButtonPress>", "<Motion>", "<MouseWheel>"):
            self.bind_all(sequence, self._touch, add="+")
        self.after(1000, self._check_idle)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.show_login()

    def _open_db(self):
        self.db = Database(self.vault_file)
        self.auth = AuthManager(self.db)
        self.settings = load_settings(self.db)

    # ---------- screens ----------

    def _swap_view(self, view):
        if self.view is not None:
            self.view.destroy()
        self.view = view
        view.pack(fill="both", expand=True)

    def show_login(self, message=None):
        self._swap_view(LoginView(self, self, message))

    def open_vault(self, vault_key):
        try:
            self.vault = VaultManager(self.db, vault_key)
        except DecryptionError:
            log.error("An entry failed to decrypt while opening the vault")
            theme.show_error(self, "Some data in the vault file is damaged or was changed, so it can't be opened.\n"
                                   "If you have a backup, you can restore it from Settings after fixing this.")
            self.show_login()
            return
        del vault_key
        self.last_activity = time.monotonic()
        self._swap_view(MainView(self, self))
        self.view.show("Dashboard")

    def lock(self, message=None, show_login=True):
        """Drop the key and every decrypted value, close any open windows, go back to login."""
        for child in self.winfo_children():
            if isinstance(child, tk.Toplevel):
                child.destroy()
        self.active_form = None
        if isinstance(self.view, MainView):
            self.view.clear()
        if self.vault is not None:
            self.vault.lock()
            self.vault = None
        self.clipboard.clear_if_ours()
        if show_login:
            self.show_login(message)

    # ---------- used by pages ----------

    def flash(self, text, colour=theme.ACCENT):
        if isinstance(self.view, MainView):
            self.view.status.configure(text=text, text_color=colour)
            if self._flash_job:
                self.after_cancel(self._flash_job)
            self._flash_job = self.after(5000, self._clear_flash)

    def _clear_flash(self):
        self._flash_job = None
        if isinstance(self.view, MainView):
            self.view.status.configure(text="")

    def copy_to_clipboard(self, text, what="Password", secret=True):
        self.clipboard.copy(text, secret=secret)
        if secret:
            self.flash(f"{what} copied. The clipboard will be cleared in {self.clipboard.clear_after_seconds} seconds.")
        else:
            self.flash(f"{what} copied.")

    def open_entry_form(self, entry=None, password=None):
        if self.vault is None:
            return
        if self.active_form is not None and self.active_form.winfo_exists():
            self.active_form.lift()
            if password:
                self.active_form.set_password(password)
            return
        self.active_form = EntryForm(self, entry, password)

    def use_generated_password(self, password):
        """Generator's "Use this password": fill the open form, or open a new one."""
        self.open_entry_form(password=password)

    def show_entry(self, entry_uuid):
        if isinstance(self.view, MainView):
            self.view.show("Vault")
            self.view.pages["Vault"].select(entry_uuid)

    def apply_settings(self, settings):
        self.settings = settings
        self.clipboard.clear_after_seconds = settings["clipboard_clear_seconds"]
        if isinstance(self.view, MainView):
            self.view.update_lock_hint()

    def restore_from_backup(self, backup_path, password):
        self.lock(show_login=False)
        self.db.close()
        message = None
        try:
            previous = backup.restore_backup(backup_path, password, self.vault_file)
            message = "Backup restored. Unlock with the backup's master password."
            if previous:
                message += f"\nYour old vault was saved as {previous.name}."
        except (AuthError, backup.BackupError) as err:
            theme.show_error(self, f"Restore failed: {err}\nYour current vault was not changed.")
        except OSError:
            self.log_exception("Restore failed")
            theme.show_error(self, "Restore failed because a file couldn't be replaced.\nYour current vault was not changed.")
        finally:
            self._open_db()
            self.apply_settings(self.settings)
        self.show_login(message)

    # ---------- auto-lock ----------

    def _touch(self, _event=None):
        self.last_activity = time.monotonic()

    def _check_idle(self):
        try:
            if self.vault is not None:
                idle = time.monotonic() - self.last_activity
                if idle >= self.settings["auto_lock_seconds"]:
                    log.info("Auto-locked after inactivity")
                    self.lock("Locked automatically after inactivity.")
        finally:
            self.after(1000, self._check_idle)

    # ---------- clipboard ----------

    def _clipboard_get(self):
        try:
            return self.clipboard_get()
        except tk.TclError:
            return ""

    def _clipboard_set(self, text):
        self.clipboard_clear()
        if text:
            self.clipboard_append(text)

    # ---------- errors and closing ----------

    def log_exception(self, what):
        # Only the type and stack are logged. The message is left out in case it ever held user data.
        import sys
        exc_type, _value, tb = sys.exc_info()
        log.error("%s: %s\n%s", what, exc_type.__name__ if exc_type else "Unknown", "".join(traceback.format_tb(tb)))

    def report_callback_exception(self, exc_type, value, tb):
        """Tk calls this for any error inside a button handler. Show a friendly message instead of a traceback."""
        log.error("Unexpected error: %s\n%s", exc_type.__name__, "".join(traceback.format_tb(tb)))
        try:
            theme.show_error(self, "Something unexpected went wrong. The details were written to the log file:\n"
                                   f"{config.log_path()}")
        except tk.TclError:
            pass

    def on_close(self):
        self.lock(show_login=False)
        self.db.close()
        self.destroy()
