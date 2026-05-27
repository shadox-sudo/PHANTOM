"""
PHANTOM — Telegram Bot Integration

Real-time scan updates via Telegram Bot API.
Pure Python — uses utils.http_client.request() for all HTTP calls.
No python-telegram-bot dependency.

Runs a polling loop in a background thread every 5 seconds.
Commands: /status, /stop, /help
"""
from __future__ import annotations
import json
import logging
import threading
import time
from typing import Optional, Callable

from utils.http_client import request as http_request

logger = logging.getLogger("phantom.tgbot")


class TelegramBot:
    """Telegram bot for real-time scan notifications.

    Args:
        token: Bot token from @BotFather.
        chat_id: Target chat ID for messages.
    """

    BASE_URL = "https://api.telegram.org/bot{token}/{method}"

    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = str(chat_id)
        self.running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._engine = None
        self._last_update_id: int = 0
        self._poll_interval: float = 5.0

        self._command_handlers: dict[str, Callable] = {
            "/status": self._cmd_status,
            "/stop": self._cmd_stop,
            "/help": self._cmd_help,
        }

    # ── Public API ─────────────────────────────────────────────

    def send_message(self, text: str) -> bool:
        """Send a text message to the configured chat.

        Args:
            text: Message text (up to 4096 chars).

        Returns:
            True if sent successfully.
        """
        if not self.token or not self.chat_id:
            return False

        url = self.BASE_URL.format(token=self.token, method="sendMessage")
        payload = json.dumps({
            "chat_id": self.chat_id,
            "text": text[:4096],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode("utf-8")

        try:
            resp = http_request(url, method="POST", data=payload,
                                headers={"Content-Type": "application/json"},
                                timeout=10)
            if resp.status == 200:
                return True
            logger.debug("Telegram send returned status %d", resp.status)
            return False
        except Exception as e:
            logger.debug("Telegram send failed: %s", e)
            return False

    def send_finding(self, finding) -> bool:
        """Format and send a vulnerability finding alert.

        Args:
            finding: Finding object (from engine.findings).

        Returns:
            True if sent successfully.
        """
        name = getattr(finding, "name", "Unknown Finding")
        sev = getattr(finding, "severity", "UNKNOWN").upper()
        url = getattr(finding, "url", "")
        param = getattr(finding, "param", "") or getattr(finding, "parameter", "")
        cve = getattr(finding, "cve", "") or getattr(finding, "cve_id", "")
        desc = getattr(finding, "description", "")

        sev_icons = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO",
        }
        tag = sev_icons.get(sev, "UNKNOWN")

        lines = [f"<b>{tag}</b>"]
        lines.append(f"<b>{name}</b>")
        if desc:
            lines.append(f"{desc}")
        lines.append(f"Endpoint: <code>{url}</code>")
        if param:
            lines.append(f"Parameter: <code>{param}</code>")
        if cve:
            lines.append(f"CVE: {cve}")

        return self.send_message("\n".join(lines))

    def send_report(self, path: str) -> bool:
        """Send a file via Telegram.

        NOTE: Telegram Bot API file upload requires multipart/form-data
        which is not supported by http_client.request() directly.
        This method sends a message with instructions instead.

        Args:
            path: Path to the report file.

        Returns:
            True if message sent successfully.
        """
        text = (
            "Report generated.\n"
            f"Local path: <code>{path}</code>\n\n"
            "To download, use a file transfer tool (scp, rsync, etc.).\n"
            "Telegram file upload is not supported in pure-urllib mode."
        )
        return self.send_message(text)

    def start_polling(self, engine=None) -> None:
        """Start the background polling thread.

        Args:
            engine: Optional PhantomEngine instance. If provided,
                   /status and /stop commands interact with the engine.
        """
        if self.running:
            return

        self._engine = engine
        self.running = True
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

        self.send_message(
            "PHANTOM scanner initialized\n"
            "Commands: /status /stop /help"
        )
        logger.info("Telegram bot started (polling every %.0fs)", self._poll_interval)

    def stop(self) -> None:
        """Stop the polling thread gracefully."""
        self.running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=3)
        logger.info("Telegram bot stopped")

    # ── Polling Loop ───────────────────────────────────────────

    def _poll_loop(self) -> None:
        """Background thread: poll getUpdates every N seconds."""
        url = self.BASE_URL.format(token=self.token, method="getUpdates")

        while self.running:
            try:
                poll_url = f"{url}?offset={self._last_update_id + 1}&timeout=10"
                resp = http_request(poll_url, method="GET", timeout=15)

                if resp.status == 200 and resp.body:
                    data = json.loads(resp.body)
                    for update in data.get("result", []):
                        self._last_update_id = update["update_id"]
                        self._process_update(update)

            except json.JSONDecodeError:
                pass
            except Exception as e:
                logger.debug("Telegram poll error: %s", e)

            time.sleep(self._poll_interval)

    def _process_update(self, update: dict) -> None:
        """Process a single Telegram update (message)."""
        message = update.get("message", {})
        chat_id = message.get("chat", {}).get("id")
        text = (message.get("text") or "").strip()

        # Filter: only respond to our configured chat
        if str(chat_id) != self.chat_id:
            return

        if not text:
            return

        cmd = text.split()[0].lower()
        handler = self._command_handlers.get(cmd)
        if handler:
            handler(message)
        else:
            self.send_message("Unknown command. Send /help")

    # ── Command Handlers ───────────────────────────────────────

    def _cmd_status(self, message: dict) -> None:
        """Handle /status — report engine state."""
        status = "running" if (self._engine and getattr(self._engine, "_running", True)) else "idle"
        target = ""

        if self._engine:
            t = getattr(self._engine, "target", None)
            if t:
                target = getattr(t, "domain", "") or getattr(t, "url", "") or getattr(t, "ip", "")
            findings = getattr(self._engine, "findings", None)
            vuln_count = len(findings.all()) if findings else 0
        else:
            vuln_count = 0

        lines = [
            "PHANTOM Status",
            f"Status: {status}",
        ]
        if target:
            lines.append(f"Target: {target}")
        lines.append(f"Findings: {vuln_count}")

        self.send_message("\n".join(lines))

    def _cmd_stop(self, message: dict) -> None:
        """Handle /stop — request graceful engine stop."""
        if self._engine:
            self._engine._running = False

        self.send_message(
            "Stop command received. Shutting down..."
        )

    def _cmd_help(self, message: dict) -> None:
        """Handle /help — show available commands."""
        help_text = (
            "PHANTOM Bot Commands\n\n"
            "/status - Check scanner status\n"
            "/stop - Request scan stop\n"
            "/help - Show this help\n\n"
            "Notifications are sent automatically during scans."
        )
        self.send_message(help_text)
