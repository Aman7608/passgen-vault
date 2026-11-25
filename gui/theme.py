"""Colours, fonts and small shared widgets for the dark theme."""

import sys
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

BG = "#0b1018"
SIDEBAR = "#0e1520"
CARD = "#141c29"
CARD_BORDER = "#1f2b3d"
INPUT = "#0f1722"
ACCENT = "#14c9a0"
ACCENT_HOVER = "#0fa585"
ACCENT_DARK = "#0d3b35"
TEXT = "#e6edf5"
MUTED = "#8796ab"
DANGER = "#ff5c6c"
DANGER_HOVER = "#d94352"
WARNING = "#ffb547"
NEUTRAL_BTN = "#223047"
NEUTRAL_HOVER = "#2c3d59"

LEVEL_COLORS = {
    "Very Weak": "#ff4d5e",
    "Weak": "#ff8a3d",
    "Medium": "#ffc93d",
    "Strong": "#3ddc84",
    "Very Strong": "#2ec8ff",
}

FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO_FAMILY = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

PAD = 20


def font(size=13, weight="normal"):
    return ctk.CTkFont(family=FONT_FAMILY, size=size, weight=weight)


def mono(size=13, weight="normal"):
    return ctk.CTkFont(family=MONO_FAMILY, size=size, weight=weight)


def card(master, **kwargs):
    return ctk.CTkFrame(master, fg_color=CARD, corner_radius=12, border_width=1, border_color=CARD_BORDER, **kwargs)


def button(master, text, command, kind="primary", **kwargs):
    colours = {
        "primary": (ACCENT, ACCENT_HOVER, "#04130f"),
        "neutral": (NEUTRAL_BTN, NEUTRAL_HOVER, TEXT),
        "danger": (DANGER, DANGER_HOVER, "#ffffff"),
        "ghost": ("transparent", NEUTRAL_BTN, TEXT),
    }
    fg, hover, text_colour = colours[kind]
    kwargs.setdefault("height", 36)
    kwargs.setdefault("font", font(13, "bold" if kind == "primary" else "normal"))
    return ctk.CTkButton(master, text=text, command=command, fg_color=fg, hover_color=hover,
                         text_color=text_colour, corner_radius=8, **kwargs)


def set_enabled(btn, enabled, kind="primary"):
    """Enable/disable a button and make the disabled state easy to see."""
    if enabled:
        fg = {"primary": ACCENT, "neutral": NEUTRAL_BTN, "danger": DANGER}[kind]
        btn.configure(state="normal", fg_color=fg)
    else:
        btn.configure(state="disabled", fg_color=NEUTRAL_BTN, text_color_disabled=MUTED)


def entry(master, placeholder="", show=None, **kwargs):
    kwargs.setdefault("height", 38)
    kwargs.setdefault("font", font(13))
    return ctk.CTkEntry(master, placeholder_text=placeholder, show=show, fg_color=INPUT,
                        border_color=CARD_BORDER, text_color=TEXT, corner_radius=8, **kwargs)


def label(master, text="", size=13, weight="normal", color=TEXT, **kwargs):
    return ctk.CTkLabel(master, text=text, font=font(size, weight), text_color=color, **kwargs)


class StrengthMeter(ctk.CTkFrame):
    """Coloured bar + level name + up to 3 tips."""

    def __init__(self, master, show_tips=True, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.columnconfigure(0, weight=1)
        self.bar = ctk.CTkProgressBar(self, height=10, corner_radius=5, fg_color=INPUT, progress_color=MUTED)
        self.bar.grid(row=0, column=0, sticky="ew", pady=(4, 2))
        self.bar.set(0)
        self.level = label(self, "", 12, "bold", MUTED)
        self.level.grid(row=0, column=1, padx=(10, 0))
        self.tips = label(self, "", 12, color=MUTED, justify="left", anchor="w", wraplength=420) if show_tips else None
        if self.tips:
            self.tips.grid(row=1, column=0, columnspan=2, sticky="w")

    def show(self, result):
        if result is None:
            self.bar.set(0)
            self.bar.configure(progress_color=INPUT)  # same as the track, so an empty meter looks empty
            self.level.configure(text="")
            if self.tips:
                self.tips.configure(text="")
            return
        colour = LEVEL_COLORS[result.level]
        self.bar.set(max(0.04, result.score / 100))
        self.bar.configure(progress_color=colour)
        self.level.configure(text=f"{result.level}  ·  ~{int(result.entropy_bits)} bits", text_color=colour)
        if self.tips:
            self.tips.configure(text="\n".join("• " + tip for tip in result.feedback))


def show_error(parent, message, title="Something went wrong"):
    messagebox.showerror(title, message, parent=parent)


def show_info(parent, message, title="PassGen Vault"):
    messagebox.showinfo(title, message, parent=parent)


def ask_yes_no(parent, message, title="Please confirm"):
    return messagebox.askyesno(title, message, parent=parent, icon="warning")


def center_on(window, parent, width, height):
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
    window.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")


class PasswordPrompt(ctk.CTkToplevel):
    """Small modal window that asks for a password. Use PasswordPrompt.ask(...)."""

    def __init__(self, parent, title, message):
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.configure(fg_color=BG)
        self.resizable(False, False)
        self.transient(parent)
        center_on(self, parent, 440, 210)
        label(self, message, 13, wraplength=380, justify="left").pack(padx=PAD, pady=(PAD, 10), anchor="w")
        self.field = entry(self, "Master password", show="•", width=400)
        self.field.pack(padx=PAD)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=PAD, pady=PAD)
        button(row, "OK", self._ok, width=110).pack(side="right")
        button(row, "Cancel", self.destroy, kind="neutral", width=110).pack(side="right", padx=(0, 10))
        self.field.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.after(100, self._grab)

    def _grab(self):
        try:
            self.grab_set()
            self.field.focus_set()
        except tk.TclError:
            pass

    def _ok(self):
        self.result = self.field.get()
        self.destroy()

    @classmethod
    def ask(cls, parent, title, message):
        prompt = cls(parent, title, message)
        parent.wait_window(prompt)
        return prompt.result
