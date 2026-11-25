"""Password generator page."""

import tkinter as tk

import customtkinter as ctk

from core.generator import MAX_LENGTH, MIN_LENGTH, GeneratorError, generate
from core.strength import check
from gui import theme
from gui.theme import PAD


class GeneratorPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.columnconfigure(0, weight=1)
        theme.label(self, "Password Generator", 24, "bold").grid(row=0, column=0, sticky="w", pady=(0, 14))

        # Output
        out = theme.card(self)
        out.grid(row=1, column=0, sticky="ew")
        out.columnconfigure(0, weight=1)
        self.output_var = tk.StringVar()
        self.output = ctk.CTkEntry(out, textvariable=self.output_var, font=theme.mono(22), height=58,
                                   fg_color=theme.INPUT, border_color=theme.CARD_BORDER, text_color=theme.TEXT,
                                   corner_radius=10, state="readonly")
        self.output.grid(row=0, column=0, columnspan=4, sticky="ew", padx=PAD, pady=(PAD, 10))
        self.meter = theme.StrengthMeter(out)
        self.meter.grid(row=1, column=0, sticky="ew", padx=PAD, pady=(0, 6))
        buttons = ctk.CTkFrame(out, fg_color="transparent")
        buttons.grid(row=2, column=0, sticky="w", padx=PAD, pady=(6, PAD))
        theme.button(buttons, "Generate again", self.regenerate, width=140).pack(side="left")
        self.copy_btn = theme.button(buttons, "Copy", self.copy, kind="neutral", width=100)
        self.copy_btn.pack(side="left", padx=10)
        self.use_btn = theme.button(buttons, "Use this password", self.use, kind="neutral", width=160)
        self.use_btn.pack(side="left")

        # Options
        opts = theme.card(self)
        opts.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        opts.columnconfigure(1, weight=1)
        theme.label(opts, "Options", 15, "bold").grid(row=0, column=0, columnspan=3, sticky="w", padx=PAD, pady=(PAD, 10))

        start = app.generator_options
        theme.label(opts, "Length", 13).grid(row=1, column=0, sticky="w", padx=PAD)
        self.length_var = tk.IntVar(value=start["length"])
        self.slider = ctk.CTkSlider(opts, from_=MIN_LENGTH, to=MAX_LENGTH, number_of_steps=MAX_LENGTH - MIN_LENGTH,
                                    command=self._slider_moved, progress_color=theme.ACCENT,
                                    button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER)
        self.slider.set(start["length"])
        self.slider.grid(row=1, column=1, sticky="ew", padx=10)
        self.length_entry = theme.entry(opts, width=70, justify="center")
        self.length_entry.insert(0, str(start["length"]))
        self.length_entry.grid(row=1, column=2, padx=(0, PAD))
        self.length_entry.bind("<Return>", self._length_typed)
        self.length_entry.bind("<FocusOut>", self._length_typed)

        self.flags = {}
        boxes = ctk.CTkFrame(opts, fg_color="transparent")
        boxes.grid(row=2, column=0, columnspan=3, sticky="w", padx=PAD, pady=(16, 4))
        for key, text in (("upper", "Uppercase (A-Z)"), ("lower", "Lowercase (a-z)"),
                          ("digits", "Numbers (0-9)"), ("symbols", "Symbols (!@#$...)")):
            var = tk.BooleanVar(value=start[key])
            ctk.CTkCheckBox(boxes, text=text, variable=var, command=self.regenerate, font=theme.font(13),
                            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER).pack(side="left", padx=(0, 22))
            self.flags[key] = var
        self.ambiguous_var = tk.BooleanVar(value=start["exclude_ambiguous"])
        ctk.CTkSwitch(opts, text="Exclude look-alike characters (O 0 I l 1)", variable=self.ambiguous_var,
                      command=self.regenerate, font=theme.font(13), progress_color=theme.ACCENT
                      ).grid(row=3, column=0, columnspan=3, sticky="w", padx=PAD, pady=(10, 4))
        self.error = theme.label(opts, "", 12, color=theme.DANGER)
        self.error.grid(row=4, column=0, columnspan=3, sticky="w", padx=PAD, pady=(4, PAD))
        self.regenerate()

    def _slider_moved(self, value):
        length = int(round(value))
        self.length_entry.delete(0, "end")
        self.length_entry.insert(0, str(length))
        self.regenerate()

    def _length_typed(self, _event=None):
        try:
            length = int(self.length_entry.get())
        except ValueError:
            length = int(round(self.slider.get()))
        length = max(MIN_LENGTH, min(MAX_LENGTH, length))
        self.length_entry.delete(0, "end")
        self.length_entry.insert(0, str(length))
        if length != int(round(self.slider.get())) or not self.output_var.get():
            self.slider.set(length)
            self.regenerate()

    def options(self):
        opts = {key: var.get() for key, var in self.flags.items()}
        opts["length"] = int(round(self.slider.get()))
        opts["exclude_ambiguous"] = self.ambiguous_var.get()
        return opts

    def regenerate(self):
        options = self.options()
        self.app.generator_options = options  # the add/edit form's Generate button uses these too
        try:
            password = generate(**options)
        except GeneratorError as err:
            self.output_var.set("")
            self.meter.show(None)
            self.error.configure(text=str(err))
            theme.set_enabled(self.copy_btn, False)
            theme.set_enabled(self.use_btn, False)
            return
        self.error.configure(text="")
        theme.set_enabled(self.copy_btn, True, "neutral")
        theme.set_enabled(self.use_btn, True, "neutral")
        self.output_var.set(password)
        self.meter.show(check(password))

    def copy(self):
        if self.output_var.get():
            self.app.copy_to_clipboard(self.output_var.get(), "Password")

    def use(self):
        if self.output_var.get():
            self.app.use_generated_password(self.output_var.get())

    def on_show(self):
        pass

    def clear(self):
        self.output_var.set("")
