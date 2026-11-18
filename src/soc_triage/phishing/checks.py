from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .parse import Link, Message, domain_of, hidden_in_words, is_ip, plain, registrable_domain, styled_letters

WEIGHTS = {"strong": 3, "medium": 2, "weak": 1}

SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co goo.gl is.gd cutt.ly rb.gy ow.ly buff.ly rebrand.ly shorturl.at "
    "clck.ru vk.cc t.ly tiny.cc lnkd.in s.id qr.ae".split()
)
EXECUTABLE = frozenset(
    "exe scr com pif bat cmd ps1 vbs vbe js jse wsf wsh hta lnk jar msi msix dll cpl reg".split()
)
DISK_IMAGES = frozenset("iso img vhd vhdx".split())
MACRO_DOCUMENTS = frozenset("docm xlsm pptm dotm xlsb xlam".split())
MARKUP = frozenset("html htm xhtml svg shtml".split())
ARCHIVES = frozenset("zip rar 7z gz tar ace cab".split())
DOCUMENT_LIKE = frozenset("pdf doc docx xls xlsx ppt pptx txt rtf jpg jpeg png gif csv".split())

URGENCY = (
    "urgent", "immediately", "within 24 hours", "within 48 hours", "action required", "final notice",
    "will be suspended", "has been suspended", "will be locked", "has been locked", "will be closed",
    "срочно", "немедленно", "в течение 24 часов", "в течение 48 часов", "будет заблокирован",
    "заблокирована", "последнее предупреждение",
)
CREDENTIAL_REQUESTS = (
    "verify your account", "confirm your account", "confirm your identity", "update your payment",
    "enter your password", "login details", "sign in to confirm", "validate your account",
    "billing details", "billing information", "payment details", "update your billing",
    "подтвердите", "введите пароль", "данные карты", "подтверждения личности",
)
# имена, которыми чаще всего прикрываются; сверяем с доменом отправителя
BRANDS = (
    "microsoft", "office 365", "outlook", "onedrive", "paypal", "apple", "icloud", "amazon", "netflix",
    "google", "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "docusign", "dhl", "fedex",
    "binance", "coinbase", "metamask",
)
_PASSED = ("pass", "bestguesspass")
_CREDENTIAL_PATH = re.compile(r"(?i)(log-?in|sign-?in|verify|account|password|secure|update|confirm|auth|wallet|bank)")
_DOMAIN_IN_TEXT = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


@dataclass
class Indicator:
    id: str
    weight: str
    title: str
    evidence: list[str]

    @property
    def score(self) -> int:
        return WEIGHTS[self.weight]


@dataclass
class Verdict:
    level: str
    label: str
    reason: str
    score: int


def _auth(message: Message, method: str) -> list:
    return [result for result in message.auth if result.method == method]


def _extension(filename: str) -> tuple[str, str]:
    # (последнее расширение, предпоследнее)
    parts = filename.lower().rstrip(". ").split(".")
    last = parts[-1] if len(parts) > 1 else ""
    inner = parts[-2] if len(parts) > 2 else ""
    return last, inner


def _text_domain(text: str) -> str:
    # домен из текста ссылки, если текст сам похож на адрес
    compact = text.strip()
    if " " in compact.strip("/ "):
        return ""
    match = _DOMAIN_IN_TEXT.search(compact)
    return registrable_domain(match.group(1)) if match else ""


def _from_domain(message: Message) -> str:
    return registrable_domain(plain(domain_of(message.from_address)))


def _nothing_passed(message: Message) -> list[str]:
    # ни spf, ни dkim, ни dmarc не прошли (и хотя бы два из них записаны)
    seen = []
    for method in ("spf", "dkim", "dmarc"):
        results = _auth(message, method)
        if any(result.result in _PASSED for result in results):
            return []
        if results:
            seen.append(f"{method}={results[0].result}")
    if len(seen) < 2:
        return []
    return seen + [f"compauth={result.result}" for result in _auth(message, "compauth")]


def _disguise_checks(message: Message) -> list[Indicator]:
    found: list[Indicator] = []
    places = (
        ("subject", message.subject), ("sender name", message.from_name),
        ("link text", " ".join(text for link in message.links for text in link.texts)),
        ("body", message.body_text),
    )
    hidden = [(label, *hidden_in_words(text)) for label, text in places]
    if sum(spots for _, spots, _ in hidden) >= 2:
        found.append(Indicator(
            "hidden-characters", "strong", "Invisible characters hidden inside words to get past filters",
            [f"{label}: {count} invisible characters in {spots} places inside words" for label, spots, count in hidden if spots],
        ))
    styled = [(label, styled_letters(text)) for label, text in
              (("subject", message.subject), ("sender name", message.from_name), ("sender address", message.from_address))]
    if sum(count for _, count in styled) >= 3:
        found.append(Indicator(
            "styled-letters", "medium", "Letters replaced with look-alike Unicode symbols",
            [f"{label}: {count} styled letters, reads as {plain(text)[:80]}" for (label, count), (_, text) in
             zip(styled, (("", message.subject), ("", message.from_name), ("", message.from_address))) if count],
        ))

    domain = plain(domain_of(message.from_address))
    name = plain(message.from_name).casefold()
    for brand in BRANDS:
        if re.search(rf"(?<![a-z]){re.escape(brand)}(?![a-z])", name) and brand.split()[0] not in domain:
            found.append(Indicator(
                "display-name-brand", "medium", "Sender name uses a well-known brand, the address is on an unrelated domain",
                [f"sender name {plain(message.from_name)[:80]}", f"actual address {message.from_address}"],
            ))
            break
    if message.from_address and "." not in domain and not is_ip(domain):
        found.append(Indicator(
            "sender-domain-invalid", "medium", "Sender domain is not a real internet domain",
            [f"From {message.from_address}"],
        ))
    return found


def _header_checks(message: Message) -> list[Indicator]:
    found: list[Indicator] = []
    from_domain = _from_domain(message)

    for result in _auth(message, "spf"):
        if result.result in ("fail", "softfail"):
            sender = result.properties.get("smtp.mailfrom", message.return_path)
            found.append(Indicator(
                "spf-" + result.result, "strong" if result.result == "fail" else "medium",
                f"SPF {result.result}: the sending server is not authorised for the envelope domain",
                [f"spf={result.result}", f"envelope sender {sender}"] if sender else [f"spf={result.result}"],
            ))
            break
    dkim = _auth(message, "dkim")
    if dkim and not any(result.result == "pass" for result in dkim):
        worst = dkim[0].result
        if worst == "fail":
            found.append(Indicator("dkim-fail", "strong", "DKIM signature did not verify", ["dkim=fail"]))
        elif worst == "none":
            found.append(Indicator("dkim-none", "weak", "No DKIM signature", ["dkim=none"]))
    for result in _auth(message, "dmarc"):
        if result.result == "fail":
            found.append(Indicator(
                "dmarc-fail", "strong",
                "DMARC fail: neither SPF nor DKIM matches the From domain",
                ["dmarc=fail", f"From domain {result.properties.get('header.from', from_domain)}"],
            ))
            break

    hard = {"spf-fail", "spf-softfail", "dkim-fail", "dmarc-fail"} & {indicator.id for indicator in found}
    empty = _nothing_passed(message)
    if empty and not hard:
        found = [indicator for indicator in found if indicator.id != "dkim-none"]
        found.append(Indicator(
            "auth-nothing-passed", "medium", "No sender authentication passed: SPF, DKIM and DMARC all came back empty",
            empty,
        ))

    reply_domain = registrable_domain(domain_of(message.reply_to)) if message.reply_to else ""
    if reply_domain and from_domain and reply_domain != from_domain:
        found.append(Indicator(
            "reply-to-mismatch", "medium", "Replies go to a different domain than the sender",
            [f"From {message.from_address}", f"Reply-To {message.reply_to}"],
        ))
    return_domain = registrable_domain(domain_of(message.envelope_from)) if message.envelope_from else ""
    if return_domain and from_domain and return_domain != from_domain:
        found.append(Indicator(
            "return-path-mismatch", "weak", "Envelope sender is on a different domain than From",
            [f"From {message.from_address}", f"envelope sender {message.envelope_from}"],
        ))

    shown = _DOMAIN_IN_TEXT.findall(message.from_name)
    spoofed = [domain for domain in shown if registrable_domain(domain) != from_domain]
    if spoofed and from_domain:
        found.append(Indicator(
            "display-name-address", "strong", "Display name shows an address on another domain",
            [f"display name {message.from_name}", f"actual address {message.from_address}"],
        ))
    if not message.message_id:
        found.append(Indicator("no-message-id", "weak", "No Message-ID header", ["Message-ID is missing"]))
    return found


def _link_notes(link: Link, from_domain: str) -> list[tuple[str, str, str, str]]:
    # (id, вес, заголовок, доказательство) по одной ссылке
    notes = []
    host = link.host
    domain = registrable_domain(host)
    try:
        parts = urlsplit(link.url)
        userinfo = parts.username is not None
        path = parts.path + ("?" + parts.query if parts.query else "")
    except ValueError:
        userinfo, path = False, ""

    for text in link.texts:
        shown = _text_domain(text)
        if shown and shown != domain:
            notes.append((
                "link-text-mismatch", "strong", "Link text shows one address, the link leads to another",
                f"shown {text} -> leads to {link.url}",
            ))
            break
    if host and is_ip(host):
        notes.append(("link-ip-host", "strong", "Link points to a bare IP address", link.url))
    if userinfo:
        notes.append(("link-userinfo", "strong", "Link hides the real host behind an @ sign", link.url))
    if "xn--" in host or any(ord(char) > 127 for char in host):
        notes.append(("link-punycode", "medium", "Link host uses non-Latin (punycode) characters", link.url))
    if domain in SHORTENERS:
        notes.append(("link-shortener", "weak", "Link goes through a URL shortener", link.url))
    name = from_domain.split(".")[0]
    if from_domain and domain != from_domain and len(name) >= 5 and name in host:
        notes.append((
            "link-sender-name-in-foreign-domain", "strong",
            "Sender's name appears inside a domain that belongs to someone else",
            f"{link.url} is registered under {domain}, not {from_domain}",
        ))
    elif from_domain and host and domain != from_domain and not is_ip(host) and _CREDENTIAL_PATH.search(path):
        notes.append((
            "link-login-on-other-domain", "medium", "Login or account link on a domain other than the sender's",
            f"{link.url} (sender domain {from_domain})",
        ))
    if link.url.lower().startswith("http://") and any("form action" in place for place in link.places):
        notes.append(("form-over-http", "medium", "Form submits over unencrypted HTTP", link.url))
    return notes


def _link_checks(message: Message) -> list[Indicator]:
    from_domain = _from_domain(message)
    grouped: dict[str, Indicator] = {}
    for link in message.links:
        for identifier, weight, title, evidence in _link_notes(link, from_domain):
            indicator = grouped.setdefault(identifier, Indicator(identifier, weight, title, []))
            if len(indicator.evidence) < 3:
                indicator.evidence.append(evidence)
    found = list(grouped.values())
    if message.html_forms:
        places = sorted({place.split(",")[0] for link in message.links for place in link.places if "form action" in place})
        where = "; ".join(place or "message body" for place in places) or "message body"
        found.append(Indicator(
            "html-form", "medium", "The message carries an HTML form",
            [f"forms: {message.html_forms}, in {where}"],
        ))
    return found


def _attachment_checks(message: Message) -> list[Indicator]:
    found: list[Indicator] = []
    groups = (
        ("attachment-double-extension", "strong", "Attachment name hides its real type behind a second extension"),
        ("attachment-executable", "strong", "Executable or script attachment"),
        ("attachment-disk-image", "medium", "Disk image attachment"),
        ("attachment-macro-document", "medium", "Office document that can run macros"),
        ("attachment-markup", "medium", "HTML or SVG attachment, a common carrier for fake login pages"),
        ("attachment-archive", "weak", "Archive attachment: content was not inspected"),
    )
    names: dict[str, list[str]] = {identifier: [] for identifier, _, _ in groups}
    for attachment in message.attachments:
        last, inner = _extension(attachment.filename)
        risky = last in EXECUTABLE or last in MARKUP or last in DISK_IMAGES
        if inner in DOCUMENT_LIKE and risky:
            names["attachment-double-extension"].append(attachment.filename)
        if last in EXECUTABLE:
            names["attachment-executable"].append(attachment.filename)
        elif last in DISK_IMAGES:
            names["attachment-disk-image"].append(attachment.filename)
        elif last in MACRO_DOCUMENTS:
            names["attachment-macro-document"].append(attachment.filename)
        elif last in MARKUP:
            names["attachment-markup"].append(attachment.filename)
        elif last in ARCHIVES:
            names["attachment-archive"].append(attachment.filename)
    for identifier, weight, title in groups:
        if names[identifier]:
            found.append(Indicator(identifier, weight, title, names[identifier][:3]))
    return found


def _content_checks(message: Message) -> list[Indicator]:
    text = plain(f"{message.subject}\n{message.body_text}").casefold()
    found: list[Indicator] = []
    urgency = [phrase for phrase in URGENCY if phrase in text]
    if urgency:
        found.append(Indicator("urgency", "weak", "Pressure to act quickly", [f'"{phrase}"' for phrase in urgency[:4]]))
    requests = [phrase for phrase in CREDENTIAL_REQUESTS if phrase in text]
    if requests:
        found.append(Indicator(
            "credential-request", "weak", "Asks the reader to confirm an account or enter credentials",
            [f'"{phrase}"' for phrase in requests[:4]],
        ))
    return found


def find_indicators(message: Message) -> list[Indicator]:
    found = (
        _header_checks(message) + _disguise_checks(message) + _link_checks(message)
        + _attachment_checks(message) + _content_checks(message)
    )
    order = {"strong": 0, "medium": 1, "weak": 2}
    return sorted(found, key=lambda indicator: order[indicator.weight])


def link_flags(message: Message) -> dict[str, list[str]]:
    # пометки по каждой ссылке для таблицы
    from_domain = _from_domain(message)
    return {link.url: [title for _, _, title, _ in _link_notes(link, from_domain)] for link in message.links}


def decide(indicators: list[Indicator]) -> Verdict:
    # фишинг только если сошлись минимум 3 признака
    score = sum(indicator.score for indicator in indicators)
    strong = sum(1 for indicator in indicators if indicator.weight == "strong")
    count = len(indicators)
    if count >= 3 and strong >= 1 and score >= 6:
        return Verdict(
            "phishing", "Likely phishing",
            f"{count} indicators, {strong} of them strong (score {score}). The verdict needs at least three.",
            score,
        )
    if score >= 2:
        return Verdict(
            "suspicious", "Suspicious, needs a manual look",
            f"Indicators: {count}, score {score}. Not enough independent signs to call it phishing.",
            score,
        )
    return Verdict(
        "clean", "No phishing indicators found",
        "These checks found nothing or one weak sign. That is not proof the message is safe.",
        score,
    )
