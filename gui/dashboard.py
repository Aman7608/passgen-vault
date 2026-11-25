"""Dashboard page: counts, security score, strength donut chart and recent entries."""

from datetime import datetime

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from core.config import OLD_PASSWORD_DAYS
from core.strength import LEVELS
from gui import theme
from gui.theme import PAD


def friendly_date(iso_text):
    try:
        return datetime.fromisoformat(iso_text).astimezone().strftime("%d %b %Y, %H:%M")
    except (TypeError, ValueError):
        return "-"


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.columnconfigure((0, 1, 2), weight=1, uniform="col")
        self.rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 14))
        theme.label(header, "Dashboard", 24, "bold").pack(side="left")
        theme.button(header, "+  Add Entry", lambda: app.open_entry_form(), width=130).pack(side="right")

        # Row of stat cards
        stats_row = ctk.CTkFrame(self, fg_color="transparent")
        stats_row.grid(row=1, column=0, columnspan=3, sticky="ew")
        stats_row.columnconfigure(tuple(range(5)), weight=1, uniform="stat")
        self.stat_labels = {}
        cards = [
            ("total", "Total entries", theme.TEXT),
            ("strong", "Strong passwords", theme.LEVEL_COLORS["Strong"]),
            ("weak", "Weak passwords", theme.LEVEL_COLORS["Very Weak"]),
            ("reused", "Reused passwords", theme.WARNING),
            ("old", f"Older than {OLD_PASSWORD_DAYS} days", theme.MUTED),
        ]
        for i, (key, title, colour) in enumerate(cards):
            box = theme.card(stats_row)
            box.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 7, 0 if i == 4 else 7))
            value = theme.label(box, "0", 30, "bold", colour)
            value.pack(padx=18, pady=(14, 0), anchor="w")
            theme.label(box, title, 12, color=theme.MUTED).pack(padx=18, pady=(0, 14), anchor="w")
            self.stat_labels[key] = value

        # Security score
        score_box = theme.card(self)
        score_box.grid(row=2, column=0, sticky="nsew", pady=(14, 0), padx=(0, 7))
        theme.label(score_box, "Security score", 15, "bold").pack(padx=PAD, pady=(PAD, 4), anchor="w")
        self.score_value = theme.label(score_box, "0", 54, "bold", theme.ACCENT)
        self.score_value.pack(padx=PAD, anchor="w")
        self.score_bar = ctk.CTkProgressBar(score_box, height=12, fg_color=theme.INPUT, progress_color=theme.ACCENT)
        self.score_bar.pack(padx=PAD, fill="x", pady=(4, 10))
        self.score_text = theme.label(score_box, "", 12, color=theme.MUTED, justify="left", wraplength=280)
        self.score_text.pack(padx=PAD, anchor="w")
        theme.label(score_box, "How it's worked out: the average strength of your passwords, "
                               "minus points for reused and old ones.", 11, color=theme.MUTED,
                    justify="left", wraplength=280).pack(padx=PAD, pady=(10, PAD), anchor="w", side="bottom")

        # Donut chart
        chart_box = theme.card(self)
        chart_box.grid(row=2, column=1, sticky="nsew", pady=(14, 0), padx=7)
        theme.label(chart_box, "Password strength", 15, "bold").pack(padx=PAD, pady=(PAD, 0), anchor="w")
        self.figure = Figure(figsize=(3.4, 3.0), dpi=100, facecolor=theme.CARD)
        self.canvas = FigureCanvasTkAgg(self.figure, master=chart_box)
        widget = self.canvas.get_tk_widget()
        widget.configure(bg=theme.CARD, highlightthickness=0)
        widget.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Recent entries
        recent_box = theme.card(self)
        recent_box.grid(row=2, column=2, sticky="nsew", pady=(14, 0), padx=(7, 0))
        theme.label(recent_box, "Recently changed", 15, "bold").pack(padx=PAD, pady=(PAD, 8), anchor="w")
        self.recent_frame = ctk.CTkFrame(recent_box, fg_color="transparent")
        self.recent_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def on_show(self):
        self.refresh()

    def refresh(self):
        vault = self.app.vault
        if vault is None:
            return
        stats = vault.stats()
        for key in self.stat_labels:
            self.stat_labels[key].configure(text=str(getattr(stats, key)))

        score = stats.security_score
        colour = theme.LEVEL_COLORS["Very Weak"] if score < 40 else theme.LEVEL_COLORS["Medium"] if score < 70 else theme.ACCENT
        self.score_value.configure(text=f"{score}" if stats.total else "–", text_color=colour)
        self.score_bar.configure(progress_color=colour)
        self.score_bar.set(score / 100)
        if not stats.total:
            summary = "Add your first entry to see your score."
        else:
            tips = []
            if stats.weak:
                tips.append(f"Change {stats.weak} weak password{'s' if stats.weak != 1 else ''}.")
            if stats.reused:
                tips.append(f"{stats.reused} entries share a password. Give each site its own.")
            if stats.old:
                tips.append(f"{stats.old} password{'s are' if stats.old != 1 else ' is'} older than {OLD_PASSWORD_DAYS} days.")
            summary = "\n".join(tips) or "Looking good. No weak, reused or old passwords."
        self.score_text.configure(text=summary)

        self._draw_chart(stats)
        self._draw_recent(stats.recent)

    def _draw_chart(self, stats):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.set_facecolor(theme.CARD)
        values = [stats.distribution[level] for level in LEVELS]
        if sum(values) == 0:
            ax.pie([1], colors=[theme.CARD_BORDER], startangle=90, wedgeprops={"width": 0.32, "edgecolor": theme.CARD})
            ax.text(0, 0, "No entries", ha="center", va="center", color=theme.MUTED, fontsize=11)
        else:
            shown = [(level, v) for level, v in zip(LEVELS, values) if v]
            ax.pie([v for _, v in shown], colors=[theme.LEVEL_COLORS[level] for level, _ in shown],
                   startangle=90, counterclock=False,
                   wedgeprops={"width": 0.32, "edgecolor": theme.CARD, "linewidth": 2})
            ax.text(0, 0.08, str(stats.total), ha="center", va="center", color=theme.TEXT, fontsize=22, fontweight="bold")
            ax.text(0, -0.2, "entries", ha="center", va="center", color=theme.MUTED, fontsize=10)
            handles = ax.patches
            ax.legend(handles, [f"{level}  {v}" for level, v in shown], loc="upper center",
                      bbox_to_anchor=(0.5, 0.02), ncol=2, frameon=False, fontsize=9, labelcolor=theme.TEXT)
        ax.set_aspect("equal")
        self.figure.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.2)
        self.canvas.draw_idle()

    def _draw_recent(self, recent):
        for child in self.recent_frame.winfo_children():
            child.destroy()
        if not recent:
            theme.label(self.recent_frame, "Nothing here yet.", 12, color=theme.MUTED).pack(padx=8, anchor="w")
            return
        for entry in recent:
            row = ctk.CTkFrame(self.recent_frame, fg_color="transparent", corner_radius=8, cursor="hand2")
            row.pack(fill="x", pady=2)
            name = theme.label(row, entry.name, 13, "bold", anchor="w")
            name.pack(fill="x", padx=10, pady=(6, 0))
            info = theme.label(row, f"{entry.category}  ·  {friendly_date(entry.updated_at)}", 11, color=theme.MUTED, anchor="w")
            info.pack(fill="x", padx=10, pady=(0, 6))
            for widget in (row, name, info):  # the whole row is clickable and highlights on hover
                widget.bind("<Button-1>", lambda _e, u=entry.uuid: self.app.show_entry(u))
                widget.bind("<Enter>", lambda _e, r=row: r.configure(fg_color=theme.NEUTRAL_BTN))
                widget.bind("<Leave>", lambda _e, r=row: r.configure(fg_color="transparent"))
