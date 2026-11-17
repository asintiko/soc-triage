from __future__ import annotations

import email
import email.header
import email.utils
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit

_TEXT_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'\x00-\x1f]+")
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F.:]+)\]")
_RECEIVED_FROM = re.compile(r"(?is)\bfrom\s+(\S+)")
_RECEIVED_BY = re.compile(r"(?is)\bby\s+(\S+)")
_RECEIVED_WITH = re.compile(r"(?is)\bwith\s+(\S+)")
_AUTH_RESULT = re.compile(r"(?i)^\s*([a-z][a-z0-9-]*)\s*=\s*([a-z]+)")
_AUTH_PROPERTY = re.compile(r"(?i)\b((?:header|smtp|policy)\.[a-z0-9_-]+)=([^\s;()]+)")

# двухуровневые публичные суффиксы; короткий список, не весь PSL
_TWO_LABEL_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.jp ne.jp or.jp co.kr com.br com.cn "
    "net.cn org.cn com.tr com.mx co.in co.za com.sg com.hk com.tw com.ua co.il com.ar com.pl "
    "co.id com.my com.ph com.vn com.sa com.eg co.th com.kz co.uz com.uz org.uz net.uz".split()
)


@dataclass
class Hop:
    from_host: str
    from_ip: str
    by_host: str
    protocol: str
    time: datetime | None
    raw: str


@dataclass
class AuthResult:
    method: str
    result: str
    properties: dict[str, str]
    source: str


@dataclass
class Link:
    url: str
    host: str
    texts: list[str] = field(default_factory=list)
    places: list[str] = field(default_factory=list)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class Message:
    subject: str = ""
    from_name: str = ""
    from_address: str = ""
    to: str = ""
    reply_to: str = ""
    return_path: str = ""
    date: datetime | None = None
    date_raw: str = ""
    message_id: str = ""
    mailer: str = ""
    originating_ip: str = ""
    hops: list[Hop] = field(default_factory=list)
    auth: list[AuthResult] = field(default_factory=list)
    auth_server: str = ""
    links: list[Link] = field(default_factory=list)
    mail_links: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    text: str = ""
    html_forms: int = 0
    sha256: str = ""
    size: int = 0


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_public_ip(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified)


def registrable_domain(host: str) -> str:
    # mail.example.co.uk -> example.co.uk
    host = host.lower().strip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(address: str) -> str:
    return address.rpartition("@")[2].lower().strip("> ")


def _decode(value) -> str:
    if value is None:
        return ""
    text = str(value)
    try:
        text = str(email.header.make_header(email.header.decode_header(text)))
    except Exception:
        pass
    return " ".join(text.split())


def _address(value) -> tuple[str, str]:
    if value is None:
        return "", ""
    name, address = email.utils.parseaddr(" ".join(str(value).split()))
    return _decode(name), address.strip().lower()


def _date(value: str) -> datetime | None:
    try:
        stamp = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    # -0000 = utc без известной зоны, приходит без смещения
    return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp


def _hop(raw: str) -> Hop:
    head, _, stamp = raw.rpartition(";")
    if not head:
        head, stamp = raw, ""
    from_match = _RECEIVED_FROM.search(head)
    by_match = _RECEIVED_BY.search(head)
    with_match = _RECEIVED_WITH.search(head)
    from_part = head[: by_match.start()] if by_match else head
    ip_match = _BRACKET_IP.search(from_part)
    return Hop(
        from_host=from_match.group(1).strip("()[];") if from_match and (not by_match or from_match.start() < by_match.start()) else "",
        from_ip=ip_match.group(1) if ip_match else "",
        by_host=by_match.group(1).strip("();") if by_match else "",
        protocol=with_match.group(1).strip("();") if with_match else "",
        time=_date(stamp.strip()) if stamp.strip() else None,
        raw=raw,
    )


def _auth_results(value: str, source: str) -> tuple[str, list[AuthResult]]:
    # разбор Authentication-Results (RFC 8601)
    without_comments = re.sub(r"\([^()]*\)", " ", value)
    parts = [part.strip() for part in without_comments.split(";")]
    server = parts[0].split()[0] if parts and parts[0] else ""
    results = []
    for part in parts[1:]:
        match = _AUTH_RESULT.match(part)
        if not match:
            continue
        properties = {name.lower(): item for name, item in _AUTH_PROPERTY.findall(part)}
        results.append(AuthResult(match.group(1).lower(), match.group(2).lower(), properties, source))
    return server, results


class _HtmlLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[str, str, str]] = []
        self.forms = 0
        self.text: list[str] = []
        self._anchor: list | None = None
        self._hidden = 0

    def _close_anchor(self) -> None:
        if self._anchor is not None:
            href, chunks = self._anchor
            self.found.append((href, " ".join("".join(chunks).split()), "link"))
            self._anchor = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag in ("script", "style"):
            self._hidden += 1
        elif tag == "a":
            self._close_anchor()
            if attributes.get("href"):
                self._anchor = [attributes["href"], []]
        elif tag == "form":
            self.forms += 1
            if attributes.get("action"):
                self.found.append((attributes["action"], "", "form action"))
        elif tag in ("img", "iframe", "embed", "script", "source") and attributes.get("src"):
            self.found.append((attributes["src"], "", f"{tag} source"))
        elif tag in ("area", "link") and attributes.get("href"):
            self.found.append((attributes["href"], "", f"{tag} href"))
        elif tag == "meta" and attributes.get("http-equiv", "").lower() == "refresh":
            _, _, target = attributes.get("content", "").partition("=")
            if target:
                self.found.append((target.strip(" '\""), "", "meta refresh"))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._hidden = max(0, self._hidden - 1)
        elif tag == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._hidden:
            return
        if self._anchor is not None:
            self._anchor[1].append(data)
        self.text.append(data)

    def close(self) -> None:
        super().close()
        self._close_anchor()


_LOOSE_SCHEME = re.compile(r"(?i)^(https?|ftp):[/\\]*")


def _normalise_url(url: str) -> str:
    # как откроет браузер: https:/\host и https:host -> https://host
    url = "".join(url.split())
    if url.startswith(("//", "\\\\", "/\\", "\\/")):
        url = "https:" + url
    return _LOOSE_SCHEME.sub(lambda match: match.group(1).lower() + "://", url)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


class _LinkCollector:
    def __init__(self) -> None:
        self.links: dict[str, Link] = {}
        self.mail: list[str] = []
        self.forms = 0
        self.text: list[str] = []

    def add(self, url: str, text: str, place: str) -> None:
        url = _normalise_url(url)
        scheme = url.split(":", 1)[0].lower()
        if scheme == "mailto":
            address = url[7:].split("?", 1)[0].lower()
            if address and address not in self.mail:
                self.mail.append(address)
            return
        if scheme not in ("http", "https", "ftp"):
            return
        link = self.links.setdefault(url, Link(url, _host(url)))
        if text and text not in link.texts:
            link.texts.append(text)
        if place not in link.places:
            link.places.append(place)

    def add_text(self, text: str, place: str) -> None:
        for match in _TEXT_URL.finditer(text):
            self.add(match.group(0).rstrip(".,;:!?)]}>'\""), "", place)

    def add_html(self, markup: str, place: str) -> None:
        parser = _HtmlLinks()
        try:
            parser.feed(markup)
            parser.close()
        except Exception:
            pass
        for url, text, kind in parser.found:
            self.add(url, text, f"{place}, {kind}" if place else kind)
        visible = " ".join(parser.text)
        self.add_text(visible, f"{place}, text" if place else "text")
        self.forms += parser.forms
        self.text.append(" ".join(visible.split()))


def _text_of(part) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def parse_eml(data: bytes) -> Message:
    parsed = email.message_from_bytes(data)
    message = Message(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    message.subject = _decode(parsed.get("Subject"))
    message.from_name, message.from_address = _address(parsed.get("From"))
    message.to = ", ".join(address for _, address in email.utils.getaddresses([str(v) for v in parsed.get_all("To") or []]))
    message.reply_to = _address(parsed.get("Reply-To"))[1]
    message.return_path = _address(parsed.get("Return-Path"))[1]
    message.date_raw = _decode(parsed.get("Date"))
    message.date = _date(message.date_raw) if message.date_raw else None
    message.message_id = _decode(parsed.get("Message-ID")).strip("<>")
    message.mailer = _decode(parsed.get("X-Mailer") or parsed.get("User-Agent"))
    message.originating_ip = _decode(parsed.get("X-Originating-IP")).strip("[] ")

    hops = [_hop(_decode(value)) for value in parsed.get_all("Received") or []]
    message.hops = list(reversed(hops))

    headers = parsed.get_all("Authentication-Results") or []
    if headers:
        message.auth_server, message.auth = _auth_results(_decode(headers[0]), "Authentication-Results")
    if not any(result.method == "spf" for result in message.auth):
        received_spf = _decode(parsed.get("Received-SPF"))
        if received_spf:
            verdict = received_spf.split()[0].lower()
            message.auth.append(AuthResult("spf", verdict, {}, "Received-SPF"))

    collector = _LinkCollector()
    plain: list[str] = []
    for part in parsed.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = _decode(part.get_filename())
        disposition = str(part.get("Content-Disposition") or "").lower()
        if filename or disposition.startswith("attachment"):
            payload = part.get_payload(decode=True) or b""
            message.attachments.append(
                Attachment(
                    filename=filename or "(no name)",
                    content_type=content_type,
                    size=len(payload),
                    md5=hashlib.md5(payload).hexdigest(),
                    sha1=hashlib.sha1(payload).hexdigest(),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            if content_type in ("text/html", "application/xhtml+xml", "image/svg+xml") or filename.lower().endswith(
                (".html", ".htm", ".svg", ".xhtml")
            ):
                collector.add_html(payload.decode("utf-8", errors="replace"), f"attachment {filename or '(no name)'}")
        elif content_type == "text/plain":
            text = _text_of(part)
            plain.append(text)
            collector.add_text(text, "text body")
        elif content_type == "text/html":
            collector.add_html(_text_of(part), "HTML body")
    message.links = list(collector.links.values())
    message.mail_links = collector.mail
    message.html_forms = collector.forms
    message.text = "\n".join(plain).strip() or "\n".join(collector.text).strip()
    return message
