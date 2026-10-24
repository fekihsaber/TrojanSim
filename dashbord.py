
import tkinter as tk
from tkinter import ttk, messagebox

from simulator import (
    simulate_execution,
    simulate_c2,
    simulate_persistence,
    simulate_data_access,
)
from detector import analyze_events


APP_TITLE = "TrojanSim | Security Monitoring Lab"

COLORS = {
    "background": "#0b1120",
    "panel": "#151f32",
    "panel_alt": "#1c2940",
    "text": "#e5edf8",
    "muted": "#94a3b8",
    "accent": "#38bdf8",
    "green": "#34d399",
    "yellow": "#fbbf24",
    "red": "#fb7185",
}


class TrojanSimDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1120x760")
        self.root.minsize(900, 650)
        self.root.configure(bg=COLORS["background"])

        self.filter_var = tk.StringVar(value="ALL")
        self.status_var = tk.StringVar(
            value="Ready | Synthetic events only"
        )

        self.event_by_iid = {}
        self.selected_event = None

        self.configure_styles()
        self.build_interface()
        self.refresh_events(initial=True)

    # ---------------------------------------------------------
    # STYLES
    # ---------------------------------------------------------

    def configure_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["panel"],
            rowheight=27,
            borderwidth=0,
            font=("Segoe UI", 9),
        )

        style.configure(
            "Treeview.Heading",
            background=COLORS["panel_alt"],
            foreground=COLORS["text"],
            font=("Segoe UI", 9, "bold"),
            padding=6,
        )

        style.map(
            "Treeview",
            background=[("selected", "#164e63")],
            foreground=[("selected", "#ffffff")],
        )

        style.configure(
            "TCombobox",
            fieldbackground=COLORS["panel_alt"],
            background=COLORS["panel_alt"],
            foreground=COLORS["text"],
            arrowcolor=COLORS["text"],
        )

    # ---------------------------------------------------------
    # INTERFACE
    # ---------------------------------------------------------

    def build_interface(self):
        header = tk.Frame(
            self.root,
            bg=COLORS["background"],
            padx=20,
            pady=10,
        )
        header.pack(fill="x")

        tk.Label(
            header,
            text="TROJANSIM",
            font=("Segoe UI", 21, "bold"),
            fg=COLORS["accent"],
            bg=COLORS["background"],
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Behavioral Simulation & Detection Lab",
            font=("Segoe UI", 10),
            fg=COLORS["muted"],
            bg=COLORS["background"],
        ).pack(anchor="w")

        # Statistics
        stats = tk.Frame(
            self.root,
            bg=COLORS["background"],
            padx=20,
        )
        stats.pack(fill="x", pady=(0, 10))

        self.total_value = self.create_stat_card(
            stats, "TOTAL EVENTS", "0", 0
        )
        self.alert_value = self.create_stat_card(
            stats, "FLAGGED EVENTS", "0", 1
        )
        self.high_value = self.create_stat_card(
            stats, "HIGH SEVERITY", "0", 2
        )

        # Main content
        content = tk.Frame(
            self.root,
            bg=COLORS["background"],
            padx=20,
        )
        content.pack(fill="both", expand=True, pady=(0, 8))

        # Toolbar
        toolbar = tk.Frame(
            content,
            bg=COLORS["background"],
        )
        toolbar.pack(fill="x", pady=(0, 5))

        tk.Label(
            toolbar,
            text="EVENT MONITOR",
            font=("Segoe UI", 11, "bold"),
            fg=COLORS["text"],
            bg=COLORS["background"],
        ).pack(side="left")

        tk.Label(
            toolbar,
            text="Severity:",
            fg=COLORS["muted"],
            bg=COLORS["background"],
        ).pack(side="right", padx=(0, 7))

        self.filter_box = ttk.Combobox(
            toolbar,
            textvariable=self.filter_var,
            values=["ALL", "INFO", "WARNING", "HIGH", "ERROR"],
            state="readonly",
            width=10,
        )
        self.filter_box.pack(side="right")
        self.filter_box.bind(
            "<<ComboboxSelected>>",
            self.on_filter_changed,
        )

        # Event table
        table_frame = tk.Frame(
            content,
            bg=COLORS["panel"],
            height=220,
        )
        table_frame.pack(fill="x")
        table_frame.pack_propagate(False)

        columns = ("timestamp", "event", "severity", "score")

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "timestamp": "TIMESTAMP",
            "event": "EVENT TYPE",
            "severity": "SEVERITY",
            "score": "RISK SCORE",
        }

        for column, heading in headings.items():
            self.tree.heading(column, text=heading)

        self.tree.column(
            "timestamp", width=220, minwidth=160, anchor="w"
        )
        self.tree.column(
            "event", width=350, minwidth=220, anchor="w"
        )
        self.tree.column(
            "severity", width=120, minwidth=90,
            anchor="center", stretch=False
        )
        self.tree.column(
            "score", width=120, minwidth=90,
            anchor="center", stretch=False
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(6, 0),
            pady=6,
        )
        scrollbar.pack(
            side="right",
            fill="y",
            padx=(0, 6),
            pady=6,
        )

        self.tree.tag_configure(
            "HIGH", foreground=COLORS["red"]
        )
        self.tree.tag_configure(
            "WARNING", foreground=COLORS["yellow"]
        )
        self.tree.tag_configure(
            "INFO", foreground=COLORS["green"]
        )
        self.tree.tag_configure(
            "ERROR", foreground=COLORS["red"]
        )

        # Update details when the selected row changes.
        self.tree.bind(
            "<<TreeviewSelect>>",
            self.on_event_selected,
        )

        # Simulation controls
        controls = tk.Frame(
            content,
            bg=COLORS["panel"],
            padx=12,
            pady=8,
        )
        controls.pack(fill="x", pady=(7, 0))

        tk.Label(
            controls,
            text="SIMULATION CONTROLS",
            font=("Segoe UI", 9, "bold"),
            fg=COLORS["text"],
            bg=COLORS["panel"],
        ).pack(anchor="w", pady=(0, 5))

        button_row = tk.Frame(
            controls,
            bg=COLORS["panel"],
        )
        button_row.pack(fill="x")

        buttons = [
            ("Simulate Execution", simulate_execution),
            ("Simulate C2", simulate_c2),
            ("Simulate Persistence", simulate_persistence),
            ("Simulate Data Access", simulate_data_access),
        ]

        for label, action in buttons:
            tk.Button(
                button_row,
                text=label,
                command=lambda fn=action, name=label:
                    self.run_scenario(fn, name),
                bg=COLORS["panel_alt"],
                fg=COLORS["text"],
                activebackground="#164e63",
                activeforeground="#ffffff",
                relief="flat",
                cursor="hand2",
                padx=9,
                pady=5,
                font=("Segoe UI", 9),
            ).pack(side="left", padx=(0, 6), pady=2)

        tk.Button(
            button_row,
            text="Refresh",
            command=self.refresh_events,
            bg=COLORS["accent"],
            fg="#082f49",
            activebackground="#7dd3fc",
            activeforeground="#082f49",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=5,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", pady=2)

        # Detection details
        details_frame = tk.Frame(
            content,
            bg=COLORS["panel_alt"],
            padx=12,
            pady=8,
        )
        details_frame.pack(fill="x", pady=(7, 0))

        tk.Label(
            details_frame,
            text="DETECTION DETAILS",
            anchor="w",
            fg=COLORS["accent"],
            bg=COLORS["panel_alt"],
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")

        self.details_text = tk.Text(
            details_frame,
            height=7,
            wrap="word",
            bg=COLORS["panel_alt"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            borderwidth=0,
            font=("Segoe UI", 9),
            padx=2,
            pady=4,
            state="disabled",
        )
        self.details_text.pack(fill="x", pady=(3, 0))

        self.set_details(
            "Select an event in the table to view its detection explanation."
        )

        # Status bar
        tk.Label(
            self.root,
            textvariable=self.status_var,
            anchor="w",
            fg=COLORS["green"],
            bg=COLORS["panel"],
            padx=20,
            pady=5,
            font=("Segoe UI", 9),
        ).pack(fill="x", side="bottom")

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    def create_stat_card(self, parent, title, value, column):
        card = tk.Frame(
            parent,
            bg=COLORS["panel"],
            padx=14,
            pady=8,
        )
        card.grid(
            row=0,
            column=column,
            sticky="ew",
            padx=(0 if column == 0 else 8, 0),
        )
        parent.columnconfigure(column, weight=1)

        tk.Label(
            card,
            text=title,
            fg=COLORS["muted"],
            bg=COLORS["panel"],
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w")

        value_label = tk.Label(
            card,
            text=value,
            fg=COLORS["text"],
            bg=COLORS["panel"],
            font=("Segoe UI", 19, "bold"),
        )
        value_label.pack(anchor="w", pady=(2, 0))

        return value_label

    # ---------------------------------------------------------
    # DETECTION DETAILS
    # ---------------------------------------------------------

    def set_details(self, text):
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")

    def on_event_selected(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return

        event_data = self.event_by_iid.get(selection[0])
        if event_data is not None:
            self.show_event_details(event_data)

    def show_event_details(self, event_data):
        # This is a class method, not a nested function.
        self.selected_event = event_data

        event_type = event_data.get("event_type", "UNKNOWN")
        description = event_data.get(
            "description", "No event description available."
        )
        severity = event_data.get("severity", "INFO")
        timestamp = event_data.get("timestamp", "Unknown")
        score = event_data.get("risk_score", 0)
        reason = event_data.get(
            "detection_reason",
            "No detection explanation available.",
        )
        recommendation = event_data.get(
            "recommendation",
            "Review the event manually if necessary.",
        )
        flagged = event_data.get("flagged", False)

        status = (
            "DETECTION RULE MATCHED"
            if flagged
            else "NO DETECTION RULE MATCHED"
        )

        details = (
            f"{status}\n"
            f"Event type: {event_type}\n"
            f"Description: {description}\n"
            f"Severity: {severity}\n"
            f"Educational risk score: {score}/100\n"
            f"Timestamp: {timestamp}\n\n"
            f"Detection reason:\n{reason}\n\n"
            f"Recommended action:\n{recommendation}"
        )

        self.set_details(details)
        self.status_var.set(
            f"Details updated | {event_type} | {severity}"
        )

    # ---------------------------------------------------------
    # EVENT MONITOR
    # ---------------------------------------------------------

    def on_filter_changed(self, _event=None):
        self.refresh_events(
            status_message=(
                f"Filter: {self.filter_var.get()} | "
                "Synthetic events only"
            )
        )

    def refresh_events(self, initial=False, status_message=None):
        try:
            events = analyze_events()
        except Exception as exc:
            self.status_var.set(f"Unable to analyze events: {exc}")
            messagebox.showerror(
                "Detection error",
                f"Could not analyze the event log:\n{exc}",
            )
            return

        previous_event = self.selected_event

        for iid in self.tree.get_children():
            self.tree.delete(iid)

        selected_filter = self.filter_var.get()
        filtered_events = [
            event for event in events
            if selected_filter == "ALL"
            or event.get("severity", "INFO") == selected_filter
        ]

        # Newest first, assuming the log is appended chronologically.
        visible_events = list(reversed(filtered_events))
        self.event_by_iid.clear()

        flagged_count = sum(
            bool(event.get("flagged", False))
            for event in events
        )
        high_count = sum(
            event.get("severity") == "HIGH"
            for event in events
        )

        self.total_value.config(text=str(len(events)))
        self.alert_value.config(text=str(flagged_count))
        self.high_value.config(text=str(high_count))

        restored_iid = None

        for index, event_data in enumerate(visible_events):
            iid = str(index)
            self.event_by_iid[iid] = event_data

            score = event_data.get("risk_score")
            score_text = (
                f"{score}/100" if score is not None else "N/A"
            )

            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    event_data.get("timestamp", ""),
                    event_data.get("event_type", "UNKNOWN"),
                    event_data.get("severity", "INFO"),
                    score_text,
                ),
                tags=(event_data.get("severity", "INFO"),),
            )

            if previous_event is not None and (
                event_data.get("timestamp")
                == previous_event.get("timestamp")
                and event_data.get("event_type")
                == previous_event.get("event_type")
                and event_data.get("description")
                == previous_event.get("description")
            ):
                restored_iid = iid

        # Restore the old selection, or select the newest visible event.
        if restored_iid is not None:
            chosen_iid = restored_iid
        elif visible_events:
            chosen_iid = "0"
        else:
            chosen_iid = None

        if chosen_iid is not None:
            self.tree.selection_set(chosen_iid)
            self.tree.focus(chosen_iid)
            self.tree.see(chosen_iid)

            selected_data = self.event_by_iid.get(chosen_iid)
            if selected_data is not None:
                self.show_event_details(selected_data)
        else:
            self.selected_event = None
            self.set_details(
                "No events match the selected severity filter."
            )

        if status_message:
            self.status_var.set(status_message)
        elif initial:
            self.status_var.set(
                f"Ready | Loaded {len(events)} synthetic event(s)"
            )
        else:
            self.status_var.set(
                f"Refreshed | Showing {len(visible_events)} "
                f"of {len(events)} events"
            )

    # ---------------------------------------------------------
    # SIMULATION
    # ---------------------------------------------------------

    def run_scenario(self, action, scenario_name):
        try:
            action()
            self.refresh_events(
                status_message=(
                    f"{scenario_name} completed | "
                    "Synthetic event logged and analyzed"
                )
            )
        except Exception as exc:
            self.status_var.set(f"Simulation failed: {exc}")
            messagebox.showerror(
                "Simulation error",
                f"The scenario could not be completed:\n{exc}",
            )


def main():
    root = tk.Tk()
    TrojanSimDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
