#!/bin/sh
# пересобрать демо-файлы и отчеты рядом с ними; запускать из корня репозитория
set -e
python demo/generate.py
analyzer logs demo/auth.log --out demo/reports/auth
analyzer logs demo/access.log --out demo/reports/access
analyzer logs demo/windows-security.json --tz-offset +05:00 --out demo/reports/windows
analyzer eml demo/suspicious.eml --out demo/reports/suspicious-email
