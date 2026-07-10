#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Strix Archer TUI
----------------
A terminal UI wrapper around strix_archer.py. Runs Archer as a subprocess and
streams its live output into a scrollable panel, with a History tab to browse
and re-open past reports and a Utilities tab (password breach check). The core
tool (strix_archer.py) is unchanged; this only needs `textual`.

Install:  pip install textual --break-system-packages
Run:      python3 strix_archer_tui.py

Looks for strix_archer.py next to this file; override with
    ARCHER_PATH=/path/to/strix_archer.py python3 strix_archer_tui.py

Authorized / lab use only — you must tick "I am authorized" before a run
(the same consent the CLI enforces).
"""

import glob
import os
import re
import shlex
import subprocess
import sys
import time

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (Button, Checkbox, Footer, Header, Input, Label,
                             OptionList, RichLog, TabbedContent, TabPane, Tree)
from textual.widgets.option_list import Option

HERE = os.path.dirname(os.path.abspath(__file__))
ARCHER = os.environ.get("ARCHER_PATH") or os.path.join(HERE, "strix_archer.py")

_HEADER_RE = re.compile(r"^[A-Z0-9][A-Z0-9 /&:.\-]{2,}$")


def colorize(line: str) -> Text:
    """Turn a plain Archer log line into a colored Text (by its marker)."""
    if any(c in line for c in "█╗╔═║╚╝┏┓┗┛┣┳┫╹╻»►◎"):
        return Text(line, style="magenta")
    if "★" in line:
        return Text(line, style="bold yellow")
    if "✔" in line:
        return Text(line, style="green")
    if "▶" in line:
        return Text(line, style="bold magenta")
    if "] ! " in line or line.strip().startswith("!"):
        return Text(line, style="yellow")
    if "dbg " in line:
        return Text(line, style="dim")
    if "→" in line:
        return Text(line, style="cyan")
    if "finished" in line:
        return Text(line, style="bold green")
    return Text(line)


def parse_report(text: str):
    """Parse an Archer .txt report into [(section_label, [lines])] (generic)."""
    sections = [("Report", [])]
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or set(s) <= set("=-─═"):        # separators / blank
            continue
        # A header is a short, mostly-uppercase line (Archer's phase titles).
        if _HEADER_RE.match(s) and len(s) <= 48:
            sections.append((s, []))
        else:
            sections[-1][1].append(line)
    return [(h, ls) for h, ls in sections if ls]


class ArcherTUI(App):
    TITLE = "Strix Archer"
    SUB_TITLE = "OSINT TUI"

    CSS = """
    #form { height: auto; border: round $primary; padding: 1 2; margin: 1 1 0 1; }
    #row  { height: auto; }
    #flags { height: auto; }
    #buttons { height: auto; }
    #log { border: round $secondary; height: 1fr; padding: 0 1; margin: 1; }
    #status { color: $text-muted; margin-top: 1; }
    Label { margin-top: 1; }
    Input { margin: 0 0 1 0; }
    Button { margin: 1 1 0 0; }
    Checkbox { width: auto; margin: 0 2 0 0; }
    #util { border: round $primary; padding: 1 2; margin: 1; height: auto; }
    #history-box { height: 1fr; margin: 1; }
    #history-list { width: 48; border: round $primary; }
    #history-tree { width: 1fr; border: round $secondary; padding: 0 1; }
    """

    BINDINGS = [
        ("f5", "run_scan", "Run"),
        ("ctrl+l", "clear_log", "Clear"),
        ("f6", "refresh_history", "Refresh history"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._scanning = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-scan"):
            with TabPane("OSINT", id="tab-scan"):
                with Vertical(id="form"):
                    yield Label("Domain  (-d)")
                    yield Input(placeholder="e.g. acme-labs.example", id="domain")
                    yield Label("Username  (-u)")
                    yield Input(placeholder="e.g. demo-user", id="username")
                    yield Label("Email  (-e)")
                    yield Input(placeholder="e.g. demo@acme-labs.example", id="email")
                    with Horizontal(id="row"):
                        yield Input(placeholder="output basename (optional)", id="output")
                        yield Input(placeholder="delay (s), e.g. 0.7", id="delay")
                    with Horizontal(id="flags"):
                        yield Checkbox("use-spiderfoot", id="use-spiderfoot")
                        yield Checkbox("I am authorized", id="authorized")
                    yield Input(placeholder="extra flags, e.g. --debug", id="extra")
                    with Horizontal(id="buttons"):
                        yield Button("▶ Run OSINT", id="run", variant="primary")
                        yield Button("Clear log", id="clear")
                        yield Button("Quit", id="quit", variant="error")
                    yield Label("Authorized / lab targets only.", id="status")
                yield RichLog(id="log", wrap=True, highlight=False, markup=False)
            with TabPane("Utilities", id="tab-util"):
                with Vertical(id="util"):
                    yield Label("Password breach check (HIBP k-anonymity — the password never leaves your machine)")
                    yield Input(placeholder="password to check", password=True, id="pw")
                    with Horizontal(id="row"):
                        yield Button("Check password", id="checkpw", variant="primary")
                        yield Button("Setup optional tools", id="setup")
            with TabPane("History", id="tab-history"):
                with Horizontal(id="history-box"):
                    yield OptionList(id="history-list")
                    yield Tree("(select a report)", id="history-tree")
                yield Button("Refresh", id="refresh-history")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_history()

    # ---- events ----
    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "quit":
            self.exit()
        elif bid == "clear":
            self.action_clear_log()
        elif bid == "run":
            self.action_run_scan()
        elif bid == "refresh-history":
            self.action_refresh_history()
        elif bid == "checkpw":
            self._run_password_check()
        elif bid == "setup":
            self._run_setup()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id:
            self._load_report(event.option_id)

    # ---- actions ----
    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_refresh_history(self) -> None:
        self._refresh_history()

    def action_run_scan(self) -> None:
        log = self.query_one("#log", RichLog)
        if self._scanning:
            log.write(Text("A run is already in progress.", style="yellow"))
            return
        d = self.query_one("#domain", Input).value.strip()
        u = self.query_one("#username", Input).value.strip()
        e = self.query_one("#email", Input).value.strip()
        if not (d or u or e):
            log.write(Text("Enter at least one target (domain, username, or email).", style="bold red"))
            return
        if not self.query_one("#authorized", Checkbox).value:
            log.write(Text("Tick 'I am authorized' to confirm you only test authorized / lab targets.", style="bold red"))
            self.query_one(TabbedContent).active = "tab-scan"
            return
        cmd = [sys.executable, ARCHER, "--no-color", "--i-am-authorized"]
        if d: cmd += ["-d", d]
        if u: cmd += ["-u", u]
        if e: cmd += ["-e", e]
        out = self.query_one("#output", Input).value.strip()
        if out: cmd += ["-o", out]
        delay = self.query_one("#delay", Input).value.strip()
        if delay: cmd += ["--delay", delay]
        if self.query_one("#use-spiderfoot", Checkbox).value:
            cmd.append("--use-spiderfoot")
        extra = self.query_one("#extra", Input).value.strip()
        if extra: cmd += shlex.split(extra)
        self._start(cmd)

    def _run_password_check(self) -> None:
        pw = self.query_one("#pw", Input).value
        if not pw:
            self._write(Text("Enter a password to check.", style="yellow"))
            return
        self.query_one(TabbedContent).active = "tab-scan"
        # Feed the password on stdin (not argv) so it never appears in the
        # process list; Archer reads one line when --check-password has no value.
        self._start([sys.executable, ARCHER, "--no-color", "--check-password"],
                    stdin_text=pw + "\n", redact="password check (input hidden)")

    def _run_setup(self) -> None:
        self.query_one(TabbedContent).active = "tab-scan"
        self._start([sys.executable, ARCHER, "--no-color", "--setup", "--i-am-authorized"])

    # ---- helpers ----
    def _start(self, cmd, stdin_text=None, redact=None) -> None:
        # `redact` shows a safe placeholder instead of echoing sensitive input.
        shown = redact or (" ".join(shlex.quote(c) for c in cmd))
        self._write(Text("$ " + shown, style="bold magenta"))
        self._scanning = True
        self.query_one("#run", Button).disabled = True
        self.query_one("#status", Label).update("Status: running…")
        self._scan_worker(cmd, stdin_text)

    def _refresh_history(self) -> None:
        ol = self.query_one("#history-list", OptionList)
        ol.clear_options()
        files = sorted(glob.glob("strix_*.txt"),
                       key=lambda f: os.path.getmtime(f), reverse=True)
        if not files:
            ol.add_option(Option("(no reports yet)", id=""))
            return
        for f in files:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(f)))
            ol.add_option(Option(f"{ts}   {f}", id=f))

    def _load_report(self, fname: str) -> None:
        tree = self.query_one("#history-tree", Tree)
        tree.reset(os.path.basename(fname))
        try:
            with open(fname, "r", errors="ignore") as fh:
                parsed = parse_report(fh.read())
        except OSError as e:
            tree.root.add_leaf(f"cannot open: {e}")
            return
        for label, lines in parsed:
            node = tree.root.add(Text(label, style="bold cyan"), expand=False)
            for ln in lines:
                node.add_leaf(ln)
        tree.root.expand()

    def _write(self, renderable) -> None:
        self.query_one("#log", RichLog).write(renderable)

    def _finish(self, report) -> None:
        self._scanning = False
        self.query_one("#run", Button).disabled = False
        msg = "Status: done" + (f"   ·   report: {report}" if report else "")
        self.query_one("#status", Label).update(msg)
        self._refresh_history()
        if report and os.path.isfile(report):
            self.query_one(TabbedContent).active = "tab-history"
            self._load_report(report)

    @work(exclusive=True, thread=True)
    def _scan_worker(self, cmd, stdin_text=None) -> None:
        report = None
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=(subprocess.PIPE if stdin_text is not None else None),
                text=True, bufsize=1)
            if stdin_text is not None:
                try:
                    proc.stdin.write(stdin_text)
                    proc.stdin.flush()
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
            for line in proc.stdout:
                line = line.rstrip("\n")
                self.call_from_thread(self._write, colorize(line))
                # Archer prints:  ✔ saved · <path>.txt
                if "saved" in line and "·" in line and line.strip().endswith(".txt"):
                    report = line.split("·", 1)[1].strip()
            proc.wait()
            self.call_from_thread(
                self._write,
                Text(f"— finished (exit {proc.returncode}) —", style="bold green"))
        except FileNotFoundError:
            self.call_from_thread(
                self._write,
                Text(f"Cannot find strix_archer.py at: {ARCHER}\n"
                     f"Put it next to this file, or set ARCHER_PATH.", style="bold red"))
        except Exception as e:  # noqa
            self.call_from_thread(self._write, Text(f"error: {e}", style="bold red"))
        finally:
            self.call_from_thread(self._finish, report)


if __name__ == "__main__":
    ArcherTUI().run()
