"""First-run setup screen and the unlock screen."""

import customtkinter as ctk

from core.auth import AuthError, LockedOutError, WeakPasswordError
from core.strength import is_acceptable_master
from gui import theme
from gui.theme import PAD


class LoginView(ctk.CTkFrame):
    def __init__(self, master, app, message=None):
        super().__init__(master, fg_color=theme.BG)
        self.app = app
        self._countdown_job = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.box = theme.card(self, width=480)
        self.box.grid(row=0, column=0)
        theme.label(self.box, "PassGen Vault", 26, "bold", theme.ACCENT).pack(padx=40, pady=(32, 4))
        theme.label(self.box, "Secure local password manager", 13, color=theme.MUTED).pack(pady=(0, 20))

        if app.auth.is_setup():
            self._build_unlock(message)
        else:
            self._build_setup()

    # ---------- first run ----------

    def _build_setup(self):
        box = self.box
        theme.label(box, "Create your master password", 16, "bold").pack(padx=40, anchor="w")
        theme.label(box, "It encrypts everything in your vault. Use a long, unique passphrase.",
                    12, color=theme.MUTED, wraplength=400, justify="left").pack(padx=40, anchor="w", pady=(2, 12))

        self.password = theme.entry(box, "Master password", show="•", width=400)
        self.password.pack(padx=40, pady=(0, 8))
        self.confirm = theme.entry(box, "Confirm master password", show="•", width=400)
        self.confirm.pack(padx=40)
        self.show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(box, text="Show password", variable=self.show_var, command=self._toggle_show,
                        font=theme.font(12), text_color=theme.MUTED, fg_color=theme.ACCENT,
                        hover_color=theme.ACCENT_HOVER, checkbox_width=18, checkbox_height=18
                        ).pack(padx=40, pady=(8, 0), anchor="w")

        self.meter = theme.StrengthMeter(box, width=400)
        self.meter.pack(padx=40, pady=(10, 0), fill="x")
        self.password.bind("<KeyRelease>", self._on_type)

        warning = ctk.CTkFrame(box, fg_color="#2a1418", corner_radius=8, border_width=1, border_color="#5c2630")
        warning.pack(padx=40, pady=(14, 0), fill="x")
        theme.label(warning, "⚠  There is NO way to recover a forgotten master password.\n"
                             "It is never stored anywhere. If you forget it, your data is gone.",
                    12, color="#ffb3bb", justify="left", wraplength=380).pack(padx=12, pady=10, anchor="w")
        self.understood = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(box, text="I understand there is no recovery", variable=self.understood,
                        font=theme.font(12), fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
                        checkbox_width=18, checkbox_height=18).pack(padx=40, pady=(10, 0), anchor="w")

        self.status = theme.label(box, "", 12, color=theme.DANGER, wraplength=400)
        self.status.pack(padx=40, pady=(8, 0))
        self.submit = theme.button(box, "Create Vault", self._create, width=400, height=42)
        self.submit.pack(padx=40, pady=(6, 32))
        self.confirm.bind("<Return>", lambda _e: self._create())
        self.after(150, self.password.focus_set)

    def _toggle_show(self):
        char = "" if self.show_var.get() else "•"
        self.password.configure(show=char)
        self.confirm.configure(show=char)

    def _on_type(self, _event=None):
        text = self.password.get()
        self.meter.show(is_acceptable_master(text)[1] if text else None)

    def _create(self):
        password, confirm = self.password.get(), self.confirm.get()
        if not password:
            return self.status.configure(text="Please enter a master password.")
        if password != confirm:
            return self.status.configure(text="The two passwords don't match.")
        if not is_acceptable_master(password)[0]:
            return self.status.configure(text="Too weak. It must be rated Strong, or be 12+ characters and at least Medium.")
        if not self.understood.get():
            return self.status.configure(text="Please tick the box to confirm you understand there is no recovery.")
        self.status.configure(text="Creating vault...", text_color=theme.MUTED)
        theme.set_enabled(self.submit, False)
        self.update_idletasks()
        try:
            key = self.app.auth.setup(password, confirm)
        except WeakPasswordError as err:
            theme.set_enabled(self.submit, True)
            return self.status.configure(text=str(err), text_color=theme.DANGER)
        except Exception:
            theme.set_enabled(self.submit, True)
            self.app.log_exception("Vault setup failed")
            return self.status.configure(text="Could not create the vault. Check the log file for details.",
                                         text_color=theme.DANGER)
        self.password.delete(0, "end")
        self.confirm.delete(0, "end")
        self.app.open_vault(key)

    # ---------- unlock ----------

    def _build_unlock(self, message):
        box = self.box
        theme.label(box, "Unlock your vault", 16, "bold").pack(padx=40, anchor="w")
        theme.label(box, "Enter your master password.", 12, color=theme.MUTED).pack(padx=40, anchor="w", pady=(2, 12))
        self.password = theme.entry(box, "Master password", show="•", width=400)
        self.password.pack(padx=40)
        self.password.bind("<Return>", lambda _e: self._unlock())
        self.status = theme.label(box, message or "", 12, color=theme.ACCENT if message else theme.DANGER, wraplength=400)
        self.status.pack(padx=40, pady=(10, 0))
        self.submit = theme.button(box, "Unlock", self._unlock, width=400, height=42)
        self.submit.pack(padx=40, pady=(6, 32))
        self.after(150, self.password.focus_set)
        self._update_lockout()

    def _unlock(self):
        if str(self.submit.cget("state")) == "disabled":
            return
        password = self.password.get()
        if not password:
            return self.status.configure(text="Please enter your master password.", text_color=theme.DANGER)
        self.status.configure(text="Unlocking...", text_color=theme.MUTED)
        theme.set_enabled(self.submit, False)
        self.update_idletasks()
        try:
            key = self.app.auth.unlock(password)
        except AuthError as err:
            self.password.delete(0, "end")
            theme.set_enabled(self.submit, True)
            self.status.configure(text=str(err), text_color=theme.DANGER)
            self._update_lockout()
            return
        except LockedOutError:
            self.password.delete(0, "end")
            self._update_lockout()
            return
        except Exception:
            theme.set_enabled(self.submit, True)
            self.app.log_exception("Unlock failed")
            return self.status.configure(text="Could not open the vault. Check the log file for details.",
                                         text_color=theme.DANGER)
        self.password.delete(0, "end")
        self.app.open_vault(key)

    def _update_lockout(self):
        """Disable the button and show a countdown while locked out."""
        remaining = self.app.auth.lockout_remaining()
        if remaining > 0:
            theme.set_enabled(self.submit, False)
            minutes, seconds = divmod(int(remaining + 0.999), 60)
            wait = f"{minutes} min {seconds:02d} s" if minutes else f"{seconds} s"
            self.status.configure(text=f"Too many failed attempts. Try again in {wait}.", text_color=theme.WARNING)
            self._countdown_job = self.after(500, self._update_lockout)
        else:
            self._countdown_job = None
            if str(self.submit.cget("state")) == "disabled":
                theme.set_enabled(self.submit, True)
                self.status.configure(text="You can try again now.", text_color=theme.MUTED)

    def destroy(self):
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
        super().destroy()
