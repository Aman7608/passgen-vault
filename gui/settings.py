"""Settings page: timers, change master password, backup and restore."""

import os
import subprocess
import sys
from datetime import datetime
from tkinter import filedialog

import customtkinter as ctk

from core import backup, config
from core.auth import AuthError, LockedOutError, WeakPasswordError
from core.settings import AUTO_LOCK_CHOICES, CLIPBOARD_CHOICES, save_settings
from core.strength import is_acceptable_master
from gui import theme
from gui.theme import PAD


def minutes_label(seconds):
    minutes = seconds // 60
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


def seconds_label(seconds):
    return f"{seconds} seconds"


class SettingsPage(ctk.CTkScrollableFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.columnconfigure((0, 1), weight=1, uniform="col")
        theme.label(self, "Settings", 24, "bold").grid(row=0, column=0, sticky="w", pady=(0, 14))
        self._build_timers()
        self._build_password()
        self._build_backup()
        self._build_about()

    # ---------- timers ----------

    def _build_timers(self):
        box = theme.card(self)
        box.grid(row=1, column=0, sticky="nsew", padx=(0, 7), pady=(0, 14))
        box.columnconfigure(1, weight=1)
        theme.label(box, "Security timers", 15, "bold").grid(row=0, column=0, columnspan=2, sticky="w", padx=PAD, pady=(PAD, 12))

        self.lock_labels = {minutes_label(s): s for s in AUTO_LOCK_CHOICES}
        self.clip_labels = {seconds_label(s): s for s in CLIPBOARD_CHOICES}
        theme.label(box, "Auto-lock after inactivity", 13).grid(row=1, column=0, sticky="w", padx=PAD, pady=6)
        self.lock_menu = self._menu(box, list(self.lock_labels))
        self.lock_menu.grid(row=1, column=1, sticky="e", padx=PAD)
        theme.label(box, "Clear copied passwords after", 13).grid(row=2, column=0, sticky="w", padx=PAD, pady=6)
        self.clip_menu = self._menu(box, list(self.clip_labels))
        self.clip_menu.grid(row=2, column=1, sticky="e", padx=PAD)
        theme.label(box, "The clipboard is only cleared if it still holds what PassGen Vault copied.\n"
                         "Note: Windows clipboard history (Win+V) may keep its own copy.",
                    11, color=theme.MUTED, justify="left", wraplength=420).grid(row=3, column=0, columnspan=2, sticky="w", padx=PAD, pady=(8, 0))
        theme.button(box, "Save settings", self._save_timers, width=140).grid(row=4, column=0, sticky="w", padx=PAD, pady=PAD)
        self._load_timers()

    def _menu(self, master, values):
        return ctk.CTkOptionMenu(master, values=values, width=150, height=34, font=theme.font(12),
                                 fg_color=theme.NEUTRAL_BTN, button_color=theme.NEUTRAL_BTN,
                                 button_hover_color=theme.NEUTRAL_HOVER, dropdown_fg_color=theme.CARD)

    def _load_timers(self):
        self.lock_menu.set(minutes_label(self.app.settings["auto_lock_seconds"]))
        self.clip_menu.set(seconds_label(self.app.settings["clipboard_clear_seconds"]))

    def _save_timers(self):
        settings = save_settings(self.app.db, self.lock_labels[self.lock_menu.get()], self.clip_labels[self.clip_menu.get()])
        self.app.apply_settings(settings)
        self.app.flash("Settings saved.")

    # ---------- change master password ----------

    def _build_password(self):
        box = theme.card(self)
        box.grid(row=1, column=1, rowspan=2, sticky="nsew", padx=(7, 0), pady=(0, 14))
        box.columnconfigure(0, weight=1)
        theme.label(box, "Change master password", 15, "bold").grid(row=0, column=0, sticky="w", padx=PAD, pady=(PAD, 4))
        theme.label(box, "Only the Vault Key gets re-wrapped, so this is quick. Entries are not re-encrypted.",
                    11, color=theme.MUTED, wraplength=420, justify="left").grid(row=1, column=0, sticky="w", padx=PAD, pady=(0, 10))
        self.old_pw = theme.entry(box, "Current master password", show="•")
        self.old_pw.grid(row=2, column=0, sticky="ew", padx=PAD, pady=4)
        self.new_pw = theme.entry(box, "New master password", show="•")
        self.new_pw.grid(row=3, column=0, sticky="ew", padx=PAD, pady=4)
        self.new_pw.bind("<KeyRelease>", self._on_new_pw)
        self.confirm_pw = theme.entry(box, "Confirm new master password", show="•")
        self.confirm_pw.grid(row=4, column=0, sticky="ew", padx=PAD, pady=4)
        self.pw_meter = theme.StrengthMeter(box)
        self.pw_meter.grid(row=5, column=0, sticky="ew", padx=PAD, pady=(6, 0))
        self.pw_status = theme.label(box, "", 12, color=theme.DANGER, wraplength=420, justify="left")
        self.pw_status.grid(row=6, column=0, sticky="w", padx=PAD, pady=(6, 0))
        theme.button(box, "Change password", self._change_password, width=170).grid(row=7, column=0, sticky="w", padx=PAD, pady=PAD)

    def _on_new_pw(self, _event=None):
        text = self.new_pw.get()
        self.pw_meter.show(is_acceptable_master(text)[1] if text else None)

    def _change_password(self):
        old, new, confirm = self.old_pw.get(), self.new_pw.get(), self.confirm_pw.get()
        if not old or not new:
            return self.pw_status.configure(text="Please fill in all three fields.", text_color=theme.DANGER)
        if new != confirm:
            return self.pw_status.configure(text="The new passwords don't match.", text_color=theme.DANGER)
        self.pw_status.configure(text="Working...", text_color=theme.MUTED)
        self.update_idletasks()
        try:
            self.app.auth.change_password(old, new, confirm)
        except (AuthError, LockedOutError, WeakPasswordError, ValueError) as err:
            self.old_pw.delete(0, "end")
            return self.pw_status.configure(text=str(err), text_color=theme.DANGER)
        for field in (self.old_pw, self.new_pw, self.confirm_pw):
            field.delete(0, "end")
        self.pw_meter.show(None)
        self.pw_status.configure(text="Master password changed. Use the new one next time you unlock.",
                                 text_color=theme.ACCENT)

    # ---------- backup ----------

    def _build_backup(self):
        box = theme.card(self)
        box.grid(row=2, column=0, sticky="nsew", padx=(0, 7), pady=(0, 14))
        theme.label(box, "Backup and restore", 15, "bold").pack(padx=PAD, pady=(PAD, 4), anchor="w")
        theme.label(box, "A backup is a copy of the encrypted vault file. It is opened with the master "
                         "password that was in use when the backup was made.",
                    11, color=theme.MUTED, wraplength=420, justify="left").pack(padx=PAD, anchor="w", pady=(0, 12))
        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(padx=PAD, pady=(0, PAD), anchor="w")
        theme.button(row, "Export backup", self._export, width=150).pack(side="left")
        theme.button(row, "Restore from backup", self._restore, kind="neutral", width=170).pack(side="left", padx=10)

    def _export(self):
        name = f"passgen-backup-{datetime.now():%Y-%m-%d}.pgvault"
        path = filedialog.asksaveasfilename(parent=self.app, title="Save encrypted backup", initialfile=name,
                                            defaultextension=".pgvault",
                                            filetypes=[("PassGen Vault backup", "*.pgvault"), ("All files", "*.*")])
        if not path:
            return
        try:
            backup.export_backup(self.app.db, path)
        except backup.BackupError as err:
            return theme.show_error(self.app, str(err))
        except OSError:
            self.app.log_exception("Backup export failed")
            return theme.show_error(self.app, "Could not write the backup file. Check the folder and try again.")
        theme.show_info(self.app, f"Backup saved to:\n{path}\n\nKeep it somewhere safe, like a USB drive.")

    def _restore(self):
        path = filedialog.askopenfilename(parent=self.app, title="Choose a backup to restore",
                                          filetypes=[("PassGen Vault backup", "*.pgvault"), ("All files", "*.*")])
        if not path:
            return
        password = theme.PasswordPrompt.ask(self.app, "Backup password",
                                            "Enter the master password that was used when this backup was made.")
        if not password:
            return
        try:
            count = backup.verify_backup(path, password)
        except AuthError:
            return theme.show_error(self.app, "Incorrect master password for this backup.", "Restore refused")
        except backup.BackupError as err:
            return theme.show_error(self.app, str(err), "Restore refused")
        if not theme.ask_yes_no(self.app, f"This backup has {count} entr{'y' if count == 1 else 'ies'}.\n\n"
                                          "Your current vault will be REPLACED by it. A copy of the current "
                                          "vault file will be kept in the data folder.\n\n"
                                          "After this, the vault locks and you unlock it with the backup's "
                                          "master password. Continue?"):
            return
        self.app.restore_from_backup(path, password)

    # ---------- about ----------

    def _build_about(self):
        box = theme.card(self)
        box.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        theme.label(box, "Storage", 15, "bold").pack(padx=PAD, pady=(PAD, 6), anchor="w")
        theme.label(box, f"Vault file:  {self.app.vault_file}", 12, color=theme.MUTED).pack(padx=PAD, anchor="w")
        theme.label(box, f"Log file:    {config.log_path()}", 12, color=theme.MUTED).pack(padx=PAD, anchor="w")
        theme.button(box, "Open data folder", self._open_folder, kind="neutral", width=160).pack(padx=PAD, pady=PAD, anchor="w")

    def _open_folder(self):
        folder = str(self.app.vault_file.parent)
        try:
            if sys.platform == "win32":
                os.startfile(folder)  # noqa: S606 - opens our own data folder in Explorer
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except OSError:
            theme.show_error(self.app, f"Could not open the folder. It is here:\n{folder}")

    def on_show(self):
        self._load_timers()

    def clear(self):
        for field in (self.old_pw, self.new_pw, self.confirm_pw):
            field.delete(0, "end")
