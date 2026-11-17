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
