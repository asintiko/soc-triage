import hashlib
from pathlib import Path

from soc_triage.defang import defang_email, defang_text, defang_url
from soc_triage.phishing import decide, find_indicators, parse_eml, registrable_domain
from soc_triage.phishing.checks import Indicator

DEMO = Path(__file__).resolve().parents[1] / "demo" / "suspicious.eml"

NEWSLETTER = b"""Return-Path: <news@shop.example>
Received: from out.shop.example (out.shop.example [192.0.2.25])
\tby mx.recipient.example with ESMTPS id 1; Tue, 10 Nov 2026 10:00:02 +0500
Authentication-Results: mx.recipient.example;
\tspf=pass smtp.mailfrom=news@shop.example;
\tdkim=pass header.d=shop.example;
\tdmarc=pass header.from=shop.example
From: Shop <news@shop.example>
To: a.karimov@recipient.example
Subject: =?utf-8?B?0J3QvtCy0LjQvdC60Lg=?= of the week
Date: Tue, 10 Nov 2026 10:00:00 +0500
Message-ID: <week-46@shop.example>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>New arrivals: <a href="https://shop.example/catalog?week=46">see the catalog</a></p></body></html>
"""


def ids(indicators):
    return {indicator.id for indicator in indicators}


def test_headers():
    message = parse_eml(DEMO.read_bytes())

    assert message.from_address == "security@examplebank.example" and message.from_name == "Example Bank Security"
    assert message.reply_to == "examplebank.support@freemail.test"
    assert message.return_path == "bounce-7731@mail.promo-sender.test"
    assert message.auth_server == "mx.recipient.example"
    assert {result.method: result.result for result in message.auth} == {"spf": "softfail", "dkim": "none", "dmarc": "fail"}
    assert message.auth[0].properties["smtp.mailfrom"] == "bounce-7731@mail.promo-sender.test"
    assert [hop.from_ip for hop in message.hops] == ["198.51.100.201", "203.0.113.77", "192.0.2.10"]
    assert message.hops[1].by_host == "mx.recipient.example" and message.hops[1].protocol == "ESMTPS"
    assert message.sha256 == hashlib.sha256(DEMO.read_bytes()).hexdigest()


def test_links():
    message = parse_eml(DEMO.read_bytes())
    links = {link.url: link for link in message.links}

    bare_ip = links["http://203.0.113.77/examplebank/verify.php?id=8841"]
    assert bare_ip.texts == ["https://examplebank.example/secure-login"]
    assert bare_ip.places == ["text body", "HTML body, link"]
    form = links["http://account-check.test/collect.php"]
    assert form.places == ["attachment Statement_November.pdf.html, form action"]
    assert message.html_forms == 1


def test_attachments():
    (attachment,) = parse_eml(DEMO.read_bytes()).attachments
    assert attachment.filename == "Statement_November.pdf.html"
    assert attachment.content_type == "text/html"
    assert len(attachment.sha256) == 64 and len(attachment.md5) == 32 and attachment.size > 300


def test_demo_verdict():
    indicators = find_indicators(parse_eml(DEMO.read_bytes()))
    verdict = decide(indicators)

    assert verdict.level == "phishing"
    assert {"dmarc-fail", "link-text-mismatch", "link-ip-host", "link-sender-name-in-foreign-domain",
            "attachment-double-extension", "reply-to-mismatch", "spf-softfail"} <= ids(indicators)
    assert indicators[0].weight == "strong"


def test_clean_mail():
    message = parse_eml(NEWSLETTER)
    assert message.subject == "Новинки of the week"
    indicators = find_indicators(message)
    assert indicators == []
    assert decide(indicators).level == "clean"


def test_verdict_min_three():
    two_strong = [Indicator("a", "strong", "a", []), Indicator("b", "strong", "b", [])]
    assert decide(two_strong).level == "suspicious"
    three = two_strong + [Indicator("c", "weak", "c", [])]
    assert decide(three).level == "phishing"
    assert decide([Indicator("w", "weak", "w", [])]).level == "clean"
    three_weak = [Indicator(name, "weak", name, []) for name in "abc"]
    assert decide(three_weak).level == "suspicious"


def test_garbage_mail():
    message = parse_eml(b"\xff\xfe not really an email\n\nhttp://192.0.2.50/x and more")
    assert message.from_address == "" and message.hops == []
    assert [link.url for link in message.links] == ["http://192.0.2.50/x"]
    assert "link-ip-host" in ids(find_indicators(message))


def test_registrable_domain():
    assert registrable_domain("login.mail.example.co.uk") == "example.co.uk"
    assert registrable_domain("a.b.shop.example") == "shop.example"
    assert registrable_domain("203.0.113.77") == "203.0.113.77"


def test_defang():
    assert defang_url("https://login.example.com/a.php?next=http://evil.example/x") == \
        "hxxps://login[.]example[.]com/a.php?next=hxxp://evil[.]example/x"
    assert defang_email("a.karimov@recipient.example") == "a.karimov[@]recipient[.]example"
    text = defang_text("Mail a.b@evil.example or open http://203.0.113.77/o.gif, see report.pdf from 198.51.100.4")
    assert text == "Mail a.b[@]evil[.]example or open hxxp://203[.]0[.]113[.]77/o.gif, see report.pdf from 198[.]51[.]100[.]4"
    assert defang_text(text) == text


def mail(headers: str, body: str = "hello", content_type: str = "text/plain") -> bytes:
    text = f"{headers.strip()}\nMIME-Version: 1.0\nContent-Type: {content_type}; charset=utf-8\n\n{body}\n"
    return text.encode("utf-8")


def test_ms_auth_header():
    # exchange online пишет результаты без имени сервера в начале
    message = parse_eml(mail(
        "From: Shop <news@shop.example>\n"
        "Authentication-Results: spf=none (sender IP is 192.0.2.44) smtp.mailfrom=bulk.example; "
        "dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=shop.example;compauth=fail reason=001"
    ))
    assert message.auth_server == ""
    assert [(r.method, r.result) for r in message.auth] == [("spf", "none"), ("dkim", "none"), ("dmarc", "none"), ("compauth", "fail")]
    assert message.envelope_from == "bulk.example"

    found = {indicator.id: indicator for indicator in find_indicators(message)}
    assert found["auth-nothing-passed"].evidence == ["spf=none", "dkim=none", "dmarc=none", "compauth=fail"]
    assert "dkim-none" not in found and "return-path-mismatch" in found


def test_sender_address_fallbacks():
    cases = {
        "From: Big Sale - Today Only! ,_<promo@shop.example>": ("Big Sale - Today Only!", "promo@shop.example"),
        'From: "Rewards Center" <"no-reply@Shop.example">': ("Rewards Center", "no-reply@shop.example"),
        "From: Voucher, <service@shop.example.>, Office, <other@shop.example>": ("Voucher", "service@shop.example"),
    }
    for header, expected in cases.items():
        message = parse_eml(mail(header))
        assert (message.from_name, message.from_address) == expected, header


def test_8bit_subject():
    message = parse_eml("From: a@shop.example\nSubject: Seu cartão — 500€\n\nx\n".encode("utf-8"))
    assert message.subject == "Seu cartão — 500€"


def test_hidden_characters():
    gap = "\U000e0139"
    subject = gap.join("Account") + " " + gap.join("locked")
    message = parse_eml(mail(f"From: Support <help@shop.example>\nSubject: {subject}"))
    found = {indicator.id: indicator for indicator in find_indicators(message)}
    assert found["hidden-characters"].weight == "strong"
    assert found["hidden-characters"].evidence == ["subject: 11 invisible characters in 11 places inside words"]

    # сердечко со своим селектором варианта - обычное письмо, не маскировка
    harmless = parse_eml(mail("From: Shop <news@shop.example>\nSubject: We \u2764\ufe0f you 1\ufe0f\u20e3 gift"))
    assert "hidden-characters" not in ids(find_indicators(harmless))


def test_styled_letters():
    bold = "".join(chr(0x1D5D4 + ord(char) - ord("A")) if char.isupper() else char for char in "OPEN NOW")
    message = parse_eml(mail(f"From: Team <team@shop.example>\nSubject: {bold}"))
    (indicator,) = [item for item in find_indicators(message) if item.id == "styled-letters"]
    assert indicator.evidence == ["subject: 7 styled letters, reads as OPEN NOW"]


def test_sender_domain_without_tld():
    message = parse_eml(mail("From: Notice <alert@agency123456>\nSubject: fine"))
    assert "sender-domain-invalid" in ids(find_indicators(message))


def test_display_name_brand():
    fake = parse_eml(mail("From: PayPal Billing <billing@garage-service.example>"))
    assert "display-name-brand" in ids(find_indicators(fake))
    glued = parse_eml(mail("From: Microsoft365 Team <team@garage-service.example>"))
    assert "display-name-brand" in ids(find_indicators(glued))
    real = parse_eml(mail("From: PayPal <service@paypal.com>"))
    assert "display-name-brand" not in ids(find_indicators(real))
    word = parse_eml(mail("From: Pineapple Farm <hi@farm.example>"))
    assert "display-name-brand" not in ids(find_indicators(word))


def test_html_in_text_part():
    body = '<table><tr><td><a href="http://192.0.2.9/pay">Update billing details</a></td></tr></table>'
    message = parse_eml(mail("From: Billing <billing@shop.example>", body))
    assert message.text == "Update billing details"
    assert message.links[0].texts == ["Update billing details"]
    assert {"link-ip-host", "credential-request"} <= ids(find_indicators(message))
