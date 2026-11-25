"""Vault page: list, search, filter, view details, and the add/edit form."""

import tkinter as tk
from datetime import datetime
from tkinter import ttk

import customtkinter as ctk

from core.generator import GeneratorError, generate
from core.strength import check, user_inputs_from_entry
from gui import theme
from gui.dashboard import friendly_date
from gui.theme import PAD

ALL_CATEGORIES = "All categories"
MASK = "••••••••••••"


def style_treeview(root):
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Vault.Treeview", background=theme.CARD, fieldbackground=theme.CARD, foreground=theme.TEXT,
                    rowheight=36, borderwidth=0, font=(theme.FONT_FAMILY, 11))
    style.map("Vault.Treeview", background=[("selected", theme.ACCENT_DARK)], foreground=[("selected", theme.TEXT)])
    style.configure("Vault.Treeview.Heading", background=theme.SIDEBAR, foreground=theme.MUTED, relief="flat",
                    font=(theme.FONT_FAMILY, 10, "bold"), padding=(8, 6))
    style.map("Vault.Treeview.Heading", background=[("active", theme.NEUTRAL_BTN)])
    style.layout("Vault.Treeview", [("Vault.Treeview.treearea", {"sticky": "nswe"})])


def short_date(iso_text):
    try:
        return datetime.fromisoformat(iso_text).astimezone().strftime("%d %b %Y")
    except (TypeError, ValueError):
        return "-"


class VaultPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.selected_uuid = None
        self.password_visible = False
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        theme.label(header, "Vault", 24, "bold").pack(side="left")
        theme.button(header, "+  Add Entry", lambda: app.open_entry_form(), width=130).pack(side="right")

        # Search + category filter
        tools = ctk.CTkFrame(self, fg_color="transparent")
        tools.grid(row=1, column=0, sticky="ew", pady=(0, 10), padx=(0, 7))
        tools.columnconfigure(0, weight=1)
        # No textvariable here: CustomTkinter hides the placeholder text when one is used.
        self.search = theme.entry(tools, "Search name, URL, username, category or notes...")
        self.search.grid(row=0, column=0, sticky="ew")
        self.search.bind("<KeyRelease>", lambda _e: self.refresh_list())
        self.category_var = tk.StringVar(value=ALL_CATEGORIES)
        self.category_menu = ctk.CTkOptionMenu(
            tools, variable=self.category_var, values=[ALL_CATEGORIES], command=lambda _v: self.refresh_list(),
            fg_color=theme.NEUTRAL_BTN, button_color=theme.NEUTRAL_BTN, button_hover_color=theme.NEUTRAL_HOVER,
            dropdown_fg_color=theme.CARD, font=theme.font(12), width=170, height=38)
        self.category_menu.grid(row=0, column=1, padx=(10, 0))

        # Entry list
        list_box = theme.card(self)
        list_box.grid(row=2, column=0, sticky="nsew", padx=(0, 7))
        list_box.rowconfigure(0, weight=1)
        list_box.columnconfigure(0, weight=1)
        style_treeview(self)
        self.tree = ttk.Treeview(list_box, style="Vault.Treeview", columns=("name", "username", "category", "updated"),
                                 show="headings", selectmode="browse")
        for col, title, width, stretch in (("name", "Name", 170, True), ("username", "Username", 170, True),
                                           ("category", "Category", 120, False), ("updated", "Modified", 115, False)):
            self.tree.heading(col, text=title, anchor="w")
            self.tree.column(col, width=width, minwidth=70, anchor="w", stretch=stretch)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scroll = ctk.CTkScrollbar(list_box, command=self.tree.yview, button_color=theme.NEUTRAL_BTN,
                                  button_hover_color=theme.NEUTRAL_HOVER)
        scroll.grid(row=0, column=1, sticky="ns", pady=8, padx=(0, 4))
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _e: self._edit())
        self.tree.bind("<Delete>", lambda _e: self._delete())
        self.count_label = theme.label(list_box, "", 11, color=theme.MUTED)
        self.count_label.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))

        # Details panel
        self.detail = theme.card(self)
        self.detail.grid(row=1, column=1, rowspan=2, sticky="nsew", padx=(7, 0))
        self._build_detail()

    # ---------- details panel ----------

    def _build_detail(self):
        d = self.detail
        d.columnconfigure(0, weight=1)
        self.empty_label = theme.label(d, "Select an entry to see its details.", 13, color=theme.MUTED)
        self.body = ctk.CTkFrame(d, fg_color="transparent")
        self.body.columnconfigure(1, weight=1)

        self.d_name = theme.label(self.body, "", 20, "bold", anchor="w", wraplength=360, justify="left")
        self.d_name.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 2))
        self.d_category = theme.label(self.body, "", 12, color=theme.ACCENT, anchor="w")
        self.d_category.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 14))

        self.d_values = {}
        rows = [("url", "Website"), ("username", "Username"), ("password", "Password")]
        for i, (key, title) in enumerate(rows, start=2):
            theme.label(self.body, title, 11, color=theme.MUTED, anchor="w").grid(row=i * 2, column=0, columnspan=3, sticky="w")
            value = theme.label(self.body, "", 13, anchor="w", wraplength=260, justify="left")
            if key == "password":
                value.configure(font=theme.mono(14))
            value.grid(row=i * 2 + 1, column=0, columnspan=2, sticky="w", pady=(0, 10))
            self.d_values[key] = value

        self.copy_user_btn = theme.button(self.body, "Copy", lambda: self._copy("username"), kind="neutral", width=64, height=30)
        self.copy_user_btn.grid(row=7, column=2, sticky="e", pady=(0, 10))
        pw_buttons = ctk.CTkFrame(self.body, fg_color="transparent")
        pw_buttons.grid(row=9, column=2, sticky="e", pady=(0, 10))
        self.show_btn = theme.button(pw_buttons, "Show", self._toggle_password, kind="neutral", width=64, height=30)
        self.show_btn.pack(side="left", padx=(0, 6))
        theme.button(pw_buttons, "Copy", lambda: self._copy("password"), kind="neutral", width=64, height=30).pack(side="left")

        self.d_meter = theme.StrengthMeter(self.body)
        self.d_meter.tips.configure(wraplength=360)
        self.d_meter.grid(row=10, column=0, columnspan=3, sticky="ew", pady=(0, 12))

        theme.label(self.body, "Notes", 11, color=theme.MUTED, anchor="w").grid(row=11, column=0, sticky="w")
        self.d_notes = ctk.CTkTextbox(self.body, height=90, fg_color=theme.INPUT, font=theme.font(12),
                                      text_color=theme.TEXT, corner_radius=8, wrap="word")
        self.d_notes.grid(row=12, column=0, columnspan=3, sticky="ew", pady=(2, 12))
        self.d_dates = theme.label(self.body, "", 11, color=theme.MUTED, anchor="w", justify="left")
        self.d_dates.grid(row=13, column=0, columnspan=3, sticky="w")

        actions = ctk.CTkFrame(self.body, fg_color="transparent")
        actions.grid(row=14, column=0, columnspan=3, sticky="ew", pady=(16, 0))
        theme.button(actions, "Edit", self._edit, width=110).pack(side="left")
        theme.button(actions, "Delete", self._delete, kind="danger", width=110).pack(side="left", padx=10)
        self._show_detail(None)

    def _show_detail(self, entry):
        self.password_visible = False
        if entry is None:
            self.body.grid_forget()
            self.empty_label.grid(row=0, column=0, padx=PAD, pady=40)
            return
        self.empty_label.grid_forget()
        self.body.grid(row=0, column=0, sticky="nsew", padx=PAD, pady=PAD)
        self.d_name.configure(text=entry.name)
        self.d_category.configure(text=entry.category)
        self.d_values["url"].configure(text=entry.url or "-")
        self.d_values["username"].configure(text=entry.username or "-")
        self.d_values["password"].configure(text=MASK)
        self.show_btn.configure(text="Show")
        self.d_meter.show(self.app.vault.strength_of(entry))
        self.d_notes.configure(state="normal")
        self.d_notes.delete("1.0", "end")
        self.d_notes.insert("1.0", entry.notes or "")
        self.d_notes.configure(state="disabled")
        self.d_dates.configure(text=f"Created: {friendly_date(entry.created_at)}\n"
                                    f"Last modified: {friendly_date(entry.updated_at)}")

    def _current(self):
        if not self.selected_uuid or self.app.vault is None:
            return None
        try:
            return self.app.vault.get(self.selected_uuid)
        except KeyError:
            return None

    def _toggle_password(self):
        entry = self._current()
        if not entry:
            return
        self.password_visible = not self.password_visible
        self.d_values["password"].configure(text=entry.password if self.password_visible else MASK)
        self.show_btn.configure(text="Hide" if self.password_visible else "Show")

    def _copy(self, field):
        entry = self._current()
        if not entry:
            return
        value = getattr(entry, field)
        if not value:
            return self.app.flash(f"This entry has no {field}.")
        self.app.copy_to_clipboard(value, field.capitalize(), secret=(field == "password"))

    def _edit(self):
        entry = self._current()
        if entry:
            self.app.open_entry_form(entry)

    def _delete(self):
        entry = self._current()
        if not entry:
            return
        if theme.ask_yes_no(self.app, f"Delete \"{entry.name}\"?\n\nThis can't be undone (unless you have a backup)."):
            self.app.vault.delete(entry.uuid)
            self.selected_uuid = None
            self.refresh()
            self.app.flash("Entry deleted.")

    # ---------- list ----------

    def _on_select(self, _event=None):
        chosen = self.tree.selection()
        self.selected_uuid = chosen[0] if chosen else None
        self._show_detail(self._current())

    def on_show(self):
        self.refresh()

    def refresh(self):
        if self.app.vault is None:
            return
        categories = [ALL_CATEGORIES] + self.app.vault.categories()
        self.category_menu.configure(values=categories)
        if self.category_var.get() not in categories:
            self.category_var.set(ALL_CATEGORIES)
        self.refresh_list()

    def refresh_list(self):
        vault = self.app.vault
        if vault is None:
            return
        category = self.category_var.get()
        entries = vault.list(self.search.get(), None if category == ALL_CATEGORIES else category)
        self.tree.delete(*self.tree.get_children())
        for entry in entries:
            self.tree.insert("", "end", iid=entry.uuid,
                             values=(entry.name, entry.username, entry.category, short_date(entry.updated_at)))
        total = vault.db.count_entries()
        self.count_label.configure(text=f"Showing {len(entries)} of {total} entries")
        if self.selected_uuid and self.tree.exists(self.selected_uuid):
            self.tree.selection_set(self.selected_uuid)
            self.tree.see(self.selected_uuid)
        else:
            self.selected_uuid = None
        self._show_detail(self._current())

    def select(self, entry_uuid):
        self.search.delete(0, "end")
        self.category_var.set(ALL_CATEGORIES)
        self.selected_uuid = entry_uuid
        self.refresh()

    def clear(self):
        """Remove every decrypted value from the widgets (used when locking)."""
        self.tree.delete(*self.tree.get_children())
        self.selected_uuid = None
        self._show_detail(None)


class EntryForm(ctk.CTkToplevel):
    """Add / edit window."""

    def __init__(self, app, entry=None, password=None):
        super().__init__(app)
        self.app = app
        self.entry = entry
        self.title("Edit entry" if entry else "Add entry")
        self.configure(fg_color=theme.BG)
        self.transient(app)
        theme.center_on(self, app, 580, 760)
        self.minsize(540, 740)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.columnconfigure(0, weight=1)

        box = ctk.CTkFrame(self, fg_color="transparent")
        box.grid(row=0, column=0, sticky="nsew", padx=PAD + 6, pady=PAD)
        box.columnconfigure(0, weight=1)
        theme.label(box, self.title(), 20, "bold").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        self.fields = {}
        row = 1
        for key, title, placeholder in (("name", "Name *", "e.g. GitHub"), ("url", "Website", "e.g. https://github.com"),
                                        ("username", "Username or email", "")):
            theme.label(box, title, 12, color=theme.MUTED).grid(row=row, column=0, sticky="w")
            field = theme.entry(box, placeholder)
            field.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(2, 10))
            field.bind("<KeyRelease>", lambda _e: self._update_meter())
            self.fields[key] = field
            row += 2

        theme.label(box, "Password *", 12, color=theme.MUTED).grid(row=row, column=0, sticky="w")
        pw_row = ctk.CTkFrame(box, fg_color="transparent")
        pw_row.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(2, 4))
        pw_row.columnconfigure(0, weight=1)
        self.password = theme.entry(pw_row, "", show="•", font=theme.mono(13))
        self.password.grid(row=0, column=0, sticky="ew")
        self.password.bind("<KeyRelease>", lambda _e: self._update_meter())
        self.show_btn = theme.button(pw_row, "Show", self._toggle_show, kind="neutral", width=64)
        self.show_btn.grid(row=0, column=1, padx=(8, 0))
        theme.button(pw_row, "Generate", self._generate, kind="neutral", width=90).grid(row=0, column=2, padx=(8, 0))
        self.meter = theme.StrengthMeter(box)
        self.meter.tips.configure(wraplength=480)
        self.meter.grid(row=row + 2, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        row += 3

        theme.label(box, "Category (pick one or type your own)", 12, color=theme.MUTED).grid(row=row, column=0, sticky="w")
        self.category = ctk.CTkComboBox(box, values=app.vault.categories(), height=38, font=theme.font(13),
                                        fg_color=theme.INPUT, border_color=theme.CARD_BORDER,
                                        button_color=theme.NEUTRAL_BTN, button_hover_color=theme.NEUTRAL_HOVER,
                                        dropdown_fg_color=theme.CARD)
        self.category.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(2, 10))
        row += 2

        theme.label(box, "Notes", 12, color=theme.MUTED).grid(row=row, column=0, sticky="w")
        self.notes = ctk.CTkTextbox(box, height=72, fg_color=theme.INPUT, border_color=theme.CARD_BORDER,
                                    border_width=1, font=theme.font(12), corner_radius=8, wrap="word")
        self.notes.grid(row=row + 1, column=0, columnspan=2, sticky="ew", pady=(2, 6))
        row += 2

        self.status = theme.label(box, "", 12, color=theme.DANGER)
        self.status.grid(row=row, column=0, columnspan=2, sticky="w")
        buttons = ctk.CTkFrame(box, fg_color="transparent")
        buttons.grid(row=row + 1, column=0, columnspan=2, sticky="e", pady=(8, 0))
        theme.button(buttons, "Cancel", self.close, kind="neutral", width=110).pack(side="left", padx=(0, 10))
        theme.button(buttons, "Save", self.save, width=110).pack(side="left")
        self.bind("<Escape>", lambda _e: self.close())

        if entry:
            self.fields["name"].insert(0, entry.name)
            self.fields["url"].insert(0, entry.url)
            self.fields["username"].insert(0, entry.username)
            self.password.insert(0, entry.password)
            self.category.set(entry.category)
            self.notes.insert("1.0", entry.notes)
        else:
            self.category.set("General")
        if password:
            self.set_password(password)
        self._update_meter()
        self.after(120, self._grab)

    def _grab(self):
        try:
            self.lift()
            self.grab_set()
            self.fields["name"].focus_set()
        except tk.TclError:
            pass

    def _toggle_show(self):
        hidden = self.password.cget("show") == "•"
        self.password.configure(show="" if hidden else "•")
        self.show_btn.configure(text="Hide" if hidden else "Show")

    def set_password(self, value):
        self.password.delete(0, "end")
        self.password.insert(0, value)
        self._update_meter()

    def _generate(self):
        try:
            self.set_password(generate(**self.app.generator_options))
        except GeneratorError as err:
            self.status.configure(text=str(err))

    def _update_meter(self):
        text = self.password.get()
        if not text:
            return self.meter.show(None)
        inputs = user_inputs_from_entry(self.fields["name"].get(), self.fields["url"].get(), self.fields["username"].get())
        self.meter.show(check(text, inputs))

    def save(self):
        values = {key: field.get() for key, field in self.fields.items()}
        values["password"] = self.password.get()
        values["category"] = self.category.get()
        values["notes"] = self.notes.get("1.0", "end-1c")
        try:
            if self.entry:
                saved = self.app.vault.update(self.entry.uuid, **values)
            else:
                saved = self.app.vault.add(**values)
        except ValueError as err:
            return self.status.configure(text=str(err))
        self.app.flash("Entry saved.")
        self.close()
        self.app.show_entry(saved.uuid)

    def close(self):
        if self.app.active_form is self:
            self.app.active_form = None
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
