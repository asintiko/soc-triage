from __future__ import annotations

import re

# схему глушим при любом продолжении после двоеточия: браузер примет и https:/\\host, и https:host
_SCHEME = re.compile(r"(?i)\b(?:(http)(s?)|(ftp))(?=:|%3a)")
_EMBEDDED = re.compile(r"(?i)\b(hxxps?|fxp)(:[/\\]*|%3a(?:%2f)*)([^/\\?#&\s]+)")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.])")
_HOST = re.compile(r"(?i)(?<![\w.\[\]-])(?:[a-z0-9_-]+\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)(?![\w\[-])")
_EMAIL = re.compile(r"(?<![\w.+-])([\w.+-]+)@((?:[\w-]+\.)*[\w-]+)")
# расширения файлов, а не домены: report.pdf не трогаем
_FILE_EXTENSIONS = frozenset(
    "html htm php pdf gif png jpg jpeg webp ico svg js css json xml txt csv log eml doc docx xls xlsx "
    "exe dll scr bat cmd asp aspx jsp cgi sql bak gz rar iso img".split()
)


def _scheme(match: re.Match) -> str:
    return f"hxxp{match.group(2)}" if match.group(1) else "fxp"


def defang_host(host: str) -> str:
    return host.replace("[.]", ".").replace(".", "[.]")


def defang_ip(address: str) -> str:
    if ":" in address and "." not in address:
        return address.replace(":", "[:]")
    return defang_host(address)


def defang_email(address: str) -> str:
    local, at, domain = address.rpartition("@")
    if not at:
        return defang_host(address)
    return f"{local}[@]{defang_host(domain)}"


def defang_url(url: str) -> str:
    # схема и хост; то же для url внутри пути и параметров
    url = _SCHEME.sub(_scheme, url)
    return _EMBEDDED.sub(lambda m: m.group(1) + m.group(2) + defang_host(m.group(3)), url)


def _sub_host(match: re.Match) -> str:
    text = match.group(0)
    if text.rsplit(".", 1)[-1].lower() in _FILE_EXTENSIONS:
        return text
    return defang_host(text)


def defang_text(text: str) -> str:
    # url, почта, ipv4 и хосты в свободном тексте
    text = defang_url(text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}[@]{defang_host(m.group(2))}", text)
    text = _IPV4.sub(lambda m: "[.]".join(m.groups()), text)
    return _HOST.sub(_sub_host, text)
