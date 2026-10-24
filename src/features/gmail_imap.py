"""
Gmail IMAP Integration Module for PhishGuard.
Connects to imap.gmail.com over SSL using a Google App Password to fetch recent
emails from Inbox or Spam for 1-click phishing analysis.
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
import re
from bs4 import BeautifulSoup


def _decode_mime_words(raw_str: str) -> str:
    """Decodes MIME-encoded header strings (e.g. =?UTF-8?B?...?=) into plain Unicode."""
    if not raw_str:
        return ""
    decoded_parts = []
    for part, encoding in decode_header(raw_str):
        if isinstance(part, bytes):
            enc = encoding or 'utf-8'
            try:
                decoded_parts.append(part.decode(enc, errors='replace'))
            except LookupError:
                decoded_parts.append(part.decode('utf-8', errors='replace'))
        else:
            decoded_parts.append(str(part))
    return "".join(decoded_parts).strip()


def _html_to_readable_text(html_content: str) -> str:
    """
    Converts an HTML email body into clean readable text while preserving
    hyperlinks (e.g. href URLs) so PhishGuard can still extract and scan them.
    """
    if not html_content:
        return ""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup(["script", "style", "head", "meta", "noscript"]):
            tag.decompose()

        # Preserve <a href="..."> URLs in the extracted text if not already visible
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            text = a_tag.get_text(strip=True)
            if href.startswith(("http://", "https://")) and href not in text:
                a_tag.append(f" ({href}) ")

        text = soup.get_text(separator="\n")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines)
    except Exception:
        return re.sub(r"<[^>]+>", " ", html_content)


def _extract_email_body(msg: email.message.Message) -> str:
    """Extracts the best readable body from a MIME email message."""
    plain_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disp = str(part.get("Content-Disposition") or "")
            if "attachment" in content_disp.lower():
                continue

            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except LookupError:
                    decoded = payload.decode("utf-8", errors="replace")

                if content_type == "text/plain" and not plain_body:
                    plain_body = decoded.strip()
                elif content_type == "text/html" and not html_body:
                    html_body = decoded.strip()
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except LookupError:
                    decoded = payload.decode("utf-8", errors="replace")

                if msg.get_content_type() == "text/html":
                    html_body = decoded.strip()
                else:
                    plain_body = decoded.strip()
        except Exception:
            pass

    if html_body:
        # If plain_body is very short or lacks links present in html_body, use cleaned HTML
        cleaned_html = _html_to_readable_text(html_body)
        if not plain_body or len(cleaned_html) > len(plain_body):
            return cleaned_html[:6000]

    return plain_body[:6000]


def _clean_claimed_org(display_name: str, sender_email: str) -> str:
    """
    Infers the Claimed Organization from the From: display name
    (e.g. 'PayPal Security <...>' -> 'PayPal').
    """
    if not display_name:
        if "@" in sender_email:
            domain_base = sender_email.split("@")[-1].split(".")[0]
            return domain_base.capitalize()
        return ""

    cleaned = re.sub(r'["\'<>]', '', display_name).strip()
    # Remove common suffixes like Support, Security, Team, Notifications, Alert
    cleaned_short = re.sub(
        r'\b(support|security|team|service|services|notifications|notification|alert|alerts|billing|account|helpdesk|no-reply|noreply|info|official)\b',
        '',
        cleaned,
        flags=re.IGNORECASE
    ).strip(" -_|:,.")

    return cleaned_short if cleaned_short else cleaned


def fetch_gmail_messages(
    gmail_address: str,
    app_password: str,
    folder: str = "INBOX",
    limit: int = 12
) -> list[dict]:
    """
    Connects to Gmail IMAP and returns the most recent `limit` emails from `folder`.
    """
    if not gmail_address or not app_password:
        raise ValueError("Gmail address and 16-character App Password are required.")

    # Strip spaces from the 16-char Google App Password (e.g. "abcd efgh ijkl mnop" -> "abcdefghijklmnop")
    clean_password = app_password.replace(" ", "").strip()
    clean_user = gmail_address.strip()

    imap_folder = "[Gmail]/Spam" if folder.upper() == "SPAM" else "INBOX"

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=10)
        mail.login(clean_user, clean_password)
    except imaplib.IMAP4.error as e:
        err_msg = str(e)
        if "Application-specific password required" in err_msg or "Invalid credentials" in err_msg or "AUTHENTICATIONFAILED" in err_msg:
            raise PermissionError(
                "Gmail login failed. Make sure you are using a 16-character Google App Password "
                "(Google Account -> Security -> 2-Step Verification -> App Passwords), not your regular password."
            )
        raise PermissionError(f"IMAP authentication error: {err_msg}")
    except Exception as e:
        raise ConnectionError(f"Could not connect to imap.gmail.com: {e}")

    messages = []
    try:
        status, _ = mail.select(f'"{imap_folder}"', readonly=True)
        if status != "OK":
            # Fallback to INBOX if [Gmail]/Spam is named differently in locale
            mail.select("INBOX", readonly=True)

        status, data = mail.search(None, "ALL")
        if status != "OK" or not data or not data[0]:
            return []

        msg_ids = data[0].split()
        recent_ids = list(reversed(msg_ids[-limit:]))

        for m_id in recent_ids:
            res, msg_data = mail.fetch(m_id, "(RFC822)")
            if res != "OK" or not msg_data or not msg_data[0]:
                continue

            raw_email = msg_data[0][1]
            if not isinstance(raw_email, bytes):
                continue

            msg = email.message_from_bytes(raw_email)

            raw_from = _decode_mime_words(msg.get("From", ""))
            display_name, sender_addr = parseaddr(raw_from)
            display_name = _decode_mime_words(display_name)
            sender_addr = sender_addr.strip().lower()

            subject = _decode_mime_words(msg.get("Subject", "(No Subject)"))
            raw_date = msg.get("Date", "")
            formatted_date = raw_date
            try:
                dt = parsedate_to_datetime(raw_date)
                formatted_date = dt.strftime("%b %d, %Y %I:%M %p")
            except Exception:
                formatted_date = raw_date[:22] if raw_date else ""

            body = _extract_email_body(msg)
            claimed_org = _clean_claimed_org(display_name, sender_addr)
            snippet = re.sub(r"\s+", " ", body)[:100] + ("..." if len(body) > 100 else "")

            messages.append({
                "id": m_id.decode("utf-8", errors="ignore"),
                "sender_name": display_name or sender_addr,
                "sender_email": sender_addr,
                "claimed_org": claimed_org,
                "subject": subject,
                "date": formatted_date,
                "body": body,
                "snippet": snippet
            })
    finally:
        try:
            mail.logout()
        except Exception:
            pass

    return messages
