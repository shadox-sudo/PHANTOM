"""
PHANTOM — Live Status Display

Shows animated spinner, current task, elapsed time, and running results
count so the user always knows something is happening.

Thread-safe: uses a lock to prevent garbled output when modules print
while the spinner is running.
"""

import sys
import threading
import time
from datetime import datetime, timedelta


class C:
    RST = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
    CYN = "\033[96m"


_original_print = print
_print_lock = threading.Lock()


def safe_print(*args, **kwargs):
    """Thread-safe print that clears spinner line first."""
    with _print_lock:
        if sys.stdout.isatty():
            sys.stdout.write("\r" + " " * 80 + "\r")
        _original_print(*args, **kwargs)
        sys.stdout.flush()


class LiveStatus:
    """Animated status line with spinner, task name, elapsed time, and counter.

    Thread-safe. Use as context manager:
        with LiveStatus("Scanning ports") as s:
            s.update("Scanning port 80...")
            s.count(5)
    """

    SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, task="Initializing...", quiet=False):
        self._task = task
        self._quiet = quiet
        self._start = time.time()
        self._count = 0
        self._extra = ""
        self._running = False
        self._thread = None

    def __enter__(self):
        if not self._quiet and sys.stdout.isatty():
            self._running = True
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *args):
        self._running = False
        if self._thread:
            self._thread.join(0.3)
        elapsed = time.time() - self._start
        if not self._quiet:
            msg = f"  [{'done':>4}] {self._task} ({elapsed:.1f}s)"
            if self._count:
                msg += f" \u2014 {self._count} results"
            safe_print(f"{C.GRN}{msg}{C.RST}")

    def update(self, task: str):
        self._task = task

    def count(self, n: int):
        self._count = n

    def extra(self, text: str):
        self._extra = text

    def _spin(self):
        i = 0
        while self._running:
            elapsed = time.time() - self._start
            spinner = self.SPINNER[i % len(self.SPINNER)]
            ts = str(timedelta(seconds=int(elapsed)))
            count_str = f" [{self._count}]" if self._count else ""
            extra_str = f" {self._extra}" if self._extra else ""
            line = f"  {C.CYN}{spinner}{C.RST} {self._task}{count_str}{extra_str} {C.DIM}{ts}{C.RST}"
            with _print_lock:
                sys.stdout.write(f"\r{line}{' '*10}")
                sys.stdout.flush()
            i += 1
            time.sleep(0.08)


def print_banner():
    b = f"""{C.RED}
██████  ██   ██  █████  ███    ██ ████████  ██████  ███    ███
██   ██ ██   ██ ██   ██ ████   ██    ██    ██    ██ ████  ████
██████  ███████ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██
██      ██   ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██
██      ██   ██ ██   ██ ██   ████    ██     ██████  ██      ██
{C.RST}
{C.DIM}  Autonomous Pentest Framework ~ Recon \u2192 Vuln \u2192 Exploit \u2192 Report{C.RST}
{C.DIM}  v1.0.0 — Built by Shadow for Musawir{C.RST}
"""
    sys.stdout.write(b)


if __name__ == "__main__":
    with LiveStatus("Testing spinner") as s:
        for i in range(50):
            s.update(f"Step {i+1}/50")
            s.count(i * 3)
            time.sleep(0.1)
