#!/usr/bin/env python3
"""
Detektor ataku brute-force na SSH na podstawie logów /var/log/auth.log.

Zasada detekcji (odpowiednik reguły w SIEM):
  jeśli z jednego adresu IP padnie >= PROG nieudanych logowań
  w oknie TIME_WINDOW sekund -> zgłoś alert.

Dodatkowo wykrywa "udane włamanie": nieudane próby z danego IP,
po których następuje udane logowanie z tego samego IP.

Na końcu zapisuje:
  - alerts.json  : alerty w formacie do dalszej integracji (np. z SIEM),
  - timeline.svg : wykres nieudanych logowań w czasie.

Uruchomienie:
    python3 detect_bruteforce.py sample_auth.log
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime

PROG = 5            # ile nieudanych prób = atak
TIME_WINDOW = 60    # w ciagu ilu sekund
ALERTS_FILE = "alerts.json"
CHART_FILE = "timeline.svg"

# Mar 19 05:25:02 ubuntuserver sshd[2049]: Failed password for tester from 192.168.1.10 port 50611 ssh2
FAILED = re.compile(r"(\w{3}\s+\d+\s[\d:]+).*?Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
ACCEPTED = re.compile(r"(\w{3}\s+\d+\s[\d:]+).*?Accepted password for (\S+) from ([\d.]+)")


def parse_time(raw):
    # log nie zawiera roku; przyjmujemy rok biezacy
    return datetime.strptime(f"{datetime.now().year} {raw}", "%Y %b %d %H:%M:%S")


def write_timeline(all_failed_times):
    """Prosty wykres słupkowy SVG: liczba nieudanych logowań na sekundę."""
    if not all_failed_times:
        return
    base = min(all_failed_times)
    buckets = defaultdict(int)
    for t in all_failed_times:
        buckets[int((t - base).total_seconds())] += 1
    span = max(buckets) + 1
    bw = max(4, min(16, 900 // span))
    maxv = max(buckets.values())
    h = 220
    width = span * bw + 60
    bars = []
    for s in range(span):
        v = buckets.get(s, 0)
        bh = int((v / maxv) * (h - 40)) if maxv else 0
        x = 40 + s * bw
        y = h - 20 - bh
        color = "#d9534f" if v >= 2 else "#5bc0de"
        bars.append(f'<rect x="{x}" y="{y}" width="{bw-1}" height="{bh}" fill="{color}"/>')
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{h}" font-family="sans-serif" font-size="11">
<text x="40" y="15" font-weight="bold">Nieudane logowania SSH w czasie (sekundy od poczatku)</text>
<line x1="40" y1="{h-20}" x2="{width-10}" y2="{h-20}" stroke="#888"/>
<text x="4" y="{h-20}">0</text>
<text x="4" y="40">{maxv}</text>
{''.join(bars)}
</svg>'''
    with open(CHART_FILE, "w", encoding="utf-8") as f:
        f.write(svg)


def main(path):
    failed = defaultdict(list)     # ip -> [(czas, uzytkownik)]
    accepted = []                  # (czas, uzytkownik, ip)

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                ts, user, ip = m.groups()
                failed[ip].append((parse_time(ts), user))
                continue
            m = ACCEPTED.search(line)
            if m:
                ts, user, ip = m.groups()
                accepted.append((parse_time(ts), user, ip))

    print("=" * 60)
    print("  RAPORT DETEKCJI - SSH BRUTE-FORCE")
    print("=" * 60)

    alerts = []
    for ip, attempts in sorted(failed.items(), key=lambda x: -len(x[1])):
        attempts.sort()
        hit = False
        for i in range(len(attempts)):
            window = [a for a in attempts
                      if 0 <= (a[0] - attempts[i][0]).total_seconds() <= TIME_WINDOW]
            if len(window) >= PROG:
                hit = True
                break
        total = len(attempts)
        users = sorted({u for _, u in attempts})
        if hit:
            breach = [a for a in accepted if a[2] == ip]
            alert = {
                "severity": "high",
                "src_ip": ip,
                "failed_attempts": total,
                "targeted_users": users,
                "first_seen": attempts[0][0].strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": attempts[-1][0].strftime("%Y-%m-%d %H:%M:%S"),
                "successful_breach": bool(breach),
                "mitre": "T1110",
            }
            if breach:
                alert["breach_user"] = breach[0][1]
                alert["breach_time"] = breach[0][0].strftime("%Y-%m-%d %H:%M:%S")
            alerts.append(alert)
            print(f"\n[ALERT] Atak brute-force z adresu {ip}")
            print(f"        Nieudane proby: {total}")
            print(f"        Atakowani uzytkownicy: {', '.join(users)}")
            print(f"        Pierwsza: {attempts[0][0]:%H:%M:%S}  ostatnia: {attempts[-1][0]:%H:%M:%S}")
            if breach:
                print(f"        !!! WLAMANIE UDANE: {breach[0][1]} zalogowany z {ip} "
                      f"o {breach[0][0]:%H:%M:%S}")
        else:
            print(f"\n[INFO]  {ip}: {total} nieudanych prob (ponizej progu {PROG}/{TIME_WINDOW}s)")

    print("\n" + "-" * 60)
    print(f"Podsumowanie: {len(alerts)} alert(ow) brute-force, "
          f"{len(accepted)} udanych logowan w logu.")
    print("-" * 60)

    # eksport alertow + wykres
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    all_failed_times = [t for lst in failed.values() for t, _ in lst]
    write_timeline(all_failed_times)
    print(f"Zapisano: {ALERTS_FILE} oraz {CHART_FILE}")


if __name__ == "__main__":
    log = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    main(log)
