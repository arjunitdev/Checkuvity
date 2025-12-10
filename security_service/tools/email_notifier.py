#!/usr/bin/env python3
"""Simple SMTP-based email notifier for security events."""

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable, List, Optional


class EmailNotifier:
    """Send email alerts when critical security events occur."""

    def __init__(self) -> None:
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_address = os.getenv("ALERT_FROM_EMAIL") or self.smtp_user
        self.default_recipients = self._parse_address_list(os.getenv("ALERT_TO_EMAILS"))
        self.default_cc = self._parse_address_list(os.getenv("ALERT_CC_EMAILS"))
        self.use_tls = os.getenv("SMTP_USE_TLS", "true").lower() != "false"

    @staticmethod
    def _parse_address_list(addresses: Optional[str]) -> List[str]:
        if not addresses:
            return []
        return [addr.strip() for addr in addresses.split(",") if addr.strip()]

    @property
    def enabled(self) -> bool:
        return bool(self.smtp_host and self.from_address and (self.smtp_user or os.getenv("SMTP_ALLOW_ANONYMOUS", "false").lower() == "true"))

    def send_hash_mismatch_alert(
        self,
        *,
        recipients: Iterable[str],
        subject: str,
        body: str,
    ) -> bool:
        """Send hash mismatch alert email.

        Args:
            recipients: Iterable of email addresses to send to.
            subject: Email subject line.
            body: Email body text.

        Returns:
            True on success, False otherwise.
        """

        if not self.enabled:
            return False

        final_recipients = list(dict.fromkeys([addr for addr in recipients if addr]))
        if not final_recipients:
            final_recipients = self.default_recipients

        if not final_recipients:
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.from_address
        message["To"] = ", ".join(final_recipients)
        if self.default_cc:
            message["Cc"] = ", ".join(self.default_cc)
            final_recipients = list(dict.fromkeys(final_recipients + self.default_cc))
        message.set_content(body)

        try:
            context = ssl.create_default_context() if self.use_tls else None
            if self.use_tls:
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                    server.starttls(context=context)
                    if self.smtp_user and self.smtp_password:
                        server.login(self.smtp_user, self.smtp_password)
                    server.send_message(message, from_addr=self.from_address, to_addrs=final_recipients)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                    if self.smtp_user and self.smtp_password:
                        server.login(self.smtp_user, self.smtp_password)
                    server.send_message(message, from_addr=self.from_address, to_addrs=final_recipients)
            return True
        except Exception:
            return False

