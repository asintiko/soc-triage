import json
from datetime import datetime

import pytest

from soc_triage.parsers import FormatError, detect_format, linux_auth, parse_text, read_text, web_access, windows
from soc_triage.timeutil import parse_offset

AUTH = """\
2026-11-10T02:10:01.123456+05:00 web-01 sshd[1001]: Failed password for root from 203.0.113.45 port 40001 ssh2
2026-11-10T02:10:02.000000+05:00 web-01 sshd[1002]: Failed password for invalid user admin from 203.0.113.45 port 40002 ssh2
2026-11-10T02:10:03.000000+05:00 web-01 sshd-session[1003]: Accepted publickey for alice from 10.0.5.12 port 51000 ssh2: ED25519 SHA256:abc
Nov 10 02:10:04 web-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update ; echo done
Nov 10 02:10:05 web-01 sudo:   bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
Nov 10 02:10:06 web-01 useradd[2001]: new user: name=svc-update, UID=1002, GID=1002, home=/home/svc-update, shell=/bin/bash
Nov 10 02:10:07 web-01 usermod[2002]: add 'svc-update' to group 'sudo'
Nov 10 02:10:08 web-01 su[2003]: FAILED SU (to root) bob on pts/1
Nov 10 02:10:09 web-01 CRON[2004]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
"""


def events_by_line(result):
    return {event.line: event for event in result.events}


def test_linux_auth():
    events = events_by_line(linux_auth.parse(AUTH, year=2026))

    assert (events[1].event, events[1].result, events[1].user, events[1].ip) == ("login", "failure", "root", "203.0.113.45")
    assert events[1].host == "web-01"
    assert events[1].time == datetime(2026, 11, 10, 2, 10, 1, 123456)
    assert events[2].user == "admin" and events[2].extra["invalid_user"] == "yes"
    assert (events[3].event, events[3].result, events[3].user) == ("login", "success", "alice")
    assert events[4].event == "sudo" and events[4].result == "success"
    assert events[4].extra["command"] == "/usr/bin/apt update ; echo done"
    assert events[4].extra["target_user"] == "root"
    assert events[5].result == "failure" and events[5].extra["reason"] == "user NOT in sudoers"
    assert (events[6].event, events[6].user) == ("account_created", "svc-update")
    assert (events[7].event, events[7].extra["group"]) == ("group_member_added", "sudo")
    assert (events[8].event, events[8].result, events[8].user) == ("su", "failure", "bob")
    assert events[9].event == "session_opened"


def test_syslog_year():
    text = "Dec 31 23:59:58 host sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n" \
           "Jan  1 00:00:03 host sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
    first, second = linux_auth.parse(text, year=2025).events
    assert first.time == datetime(2025, 12, 31, 23, 59, 58)
    assert second.time == datetime(2026, 1, 1, 0, 0, 3)


def test_broken_lines():
    text = "garbage\n" + AUTH + "2026-11-10T02:1\n\x00\x00\x00\n2026-13-45T99:00:00+05:00 web-01 sshd[1]: x\n"
    result = linux_auth.parse(text, year=2026)
    assert len(result.events) == 9
    assert [item.line for item in result.skipped] == [1, 11, 12, 13]
    assert result.skipped[-1].reason == "unreadable timestamp"


ACCESS = """\
203.0.113.99 - - [10/Nov/2026:13:55:36 +0500] "GET /.env HTTP/1.1" 404 153 "-" "sqlmap/1.9.4#stable (https://sqlmap.org)"
203.0.113.99 - - [10/Nov/2026:13:55:38 +0500] "GET /download?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 400 0 "-" "curl/8.5.0"
shop.example:443 198.51.100.7 - alice [10/Nov/2026:13:55:39 +0500] "POST /login HTTP/2.0" 302 0 "https://shop.example/" "Mozilla/5.0"
198.51.100.9 - - [10/Nov/2026:13:55:40 +0500] "\\x16\\x03\\x01\\x02" 400 157 "-" "-"
192.0.2.4 - - [10/Nov/2026:13:55:41 +0500] "GET /a\\"b HTTP/1.1" 200 12
not a log line
"""


def test_access_log():
    result = web_access.parse(ACCESS)
    events = events_by_line(result)

    assert events[1].ip == "203.0.113.99" and events[1].extra["status"] == "404" and events[1].result == "failure"
    assert events[1].extra["user_agent"].startswith("sqlmap")
    assert events[2].extra["target"] == "/download?file=../../etc/passwd"
    assert events[2].extra["path"] == "/download" and events[2].extra["query"] == "file=../../etc/passwd"
    assert (events[3].host, events[3].user, events[3].result) == ("shop.example", "alice", "success")
    assert events[4].extra["method"] == "" and events[4].extra["status"] == "400"
    assert events[5].extra["path"] == '/a\\"b' and "user_agent" not in events[5].extra
    assert [item.line for item in result.skipped] == [6]


FLAT = [
    {"TimeCreated": "2026-11-09T22:05:09.1234567Z", "EventID": 4625, "Computer": "WS-07", "TargetUserName": "Administrator",
     "IpAddress": "::ffff:10.0.8.77", "LogonType": 3, "SubjectUserName": "-"},
    {"TimeCreated": "2026-11-09T22:14:02.0000000Z", "EventID": 4732, "Computer": "WS-07", "SubjectUserName": "Administrator",
     "TargetUserName": "Administrators", "MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1124"},
    {"TimeCreated": "not a date", "EventID": 4624},
    {"Computer": "WS-07"},
]


def test_win_flat_json():
    result = windows.parse(json.dumps(FLAT), tz=parse_offset("+05:00"))
    failed, group = result.events

    assert (failed.event, failed.result, failed.user, failed.ip) == ("login", "failure", "Administrator", "10.0.8.77")
    assert failed.time == datetime(2026, 11, 10, 3, 5, 9, 123456)
    assert failed.extra["event_id"] == "4625" and failed.extra["logon_type"] == "3"
    assert group.event == "group_member_added" and group.user == "S-1-5-21-1-2-3-1124"
    assert group.extra["group"] == "Administrators" and group.extra["actor"] == "Administrator"
    assert [item.reason for item in result.skipped] == ["unreadable timestamp", "no event id"]


def test_win_evtx_dump():
    record = {"Event": {"System": {
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        "EventID": {"#attributes": {"Qualifiers": 0}, "#text": 4624},
        "TimeCreated": {"#attributes": {"SystemTime": "2026-11-10T03:10:00.000000Z"}},
        "Computer": "DC-01", "Channel": "Security"},
        "EventData": {"TargetUserName": "j.smith", "IpAddress": "10.0.8.31", "LogonType": 10}}}
    cleared = {"Event": {"System": {"EventID": 1102, "TimeCreated": {"#attributes": {"SystemTime": "2026-11-10T03:38:00Z"}},
                                    "Computer": "DC-01"},
                         "UserData": {"LogFileCleared": {"#attributes": {"xmlns": "x"}, "SubjectUserName": "Administrator"}}}}
    text = "Record 1\n" + json.dumps(record, indent=2) + "\nRecord 2\n" + json.dumps(cleared) + "\n{broken\n"
    result = windows.parse(text)

    login, wiped = result.events
    assert (login.event, login.user, login.ip, login.host) == ("login", "j.smith", "10.0.8.31", "DC-01")
    assert (wiped.event, wiped.user) == ("log_cleared", "Administrator")
    assert len(result.skipped) == 1


def test_win_evtxecmd_csv():
    payload = json.dumps({"EventData": {"Data": [
        {"@Name": "TargetUserName", "#text": "svc-backup"}, {"@Name": "IpAddress", "#text": "10.0.8.90"},
        {"@Name": "LogonType", "#text": "3"}]}})
    text = "RecordNumber,TimeCreated,EventId,Computer,Payload\n" \
           f'1,2026-11-10 03:10:00.1234567,4625,WS-07,"{payload.replace(chr(34), chr(34) * 2)}"\n'
    (event,) = windows.parse(text).events
    assert (event.event, event.result, event.user, event.ip) == ("login", "failure", "svc-backup", "10.0.8.90")


def test_win_message_only():
    message = (
        "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\n"
        "Logon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n"
        "\tAccount Name:\t\tadmin\n\nNetwork Information:\n\tWorkstation Name:\tWS-GUEST-03\n"
        "\tSource Network Address:\t203.0.113.5\n"
    )
    text = 'TimeCreated,Id,MachineName,Message\n"11/10/2026 3:05:09 AM",4625,WS-07,"' + message + '"\n'
    (event,) = windows.parse(text).events
    assert (event.user, event.ip, event.extra["logon_type"]) == ("admin", "203.0.113.5", "3")
    assert event.time == datetime(2026, 11, 10, 3, 5, 9)


@pytest.mark.parametrize("text, expected", [
    (AUTH, "linux"),
    (ACCESS, "web"),
    (json.dumps(FLAT), "windows"),
    ("TimeCreated,EventID,Computer\n2026-11-10 03:00:00,4624,WS\n", "windows"),
])
def test_detect_format(text, expected):
    assert detect_format(text) == expected


def test_unknown_format():
    with pytest.raises(FormatError):
        parse_text("hello\nworld\n")


def test_utf16(tmp_path):
    path = tmp_path / "security.json"
    path.write_bytes(json.dumps(FLAT[:1]).encode("utf-16"))
    fmt, result = parse_text(read_text(path))
    assert fmt == "windows" and len(result.events) == 1
