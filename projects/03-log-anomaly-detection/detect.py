"""Login-log anomaly detection: rules + per-user statistical baselines, scored against known incidents.

    python detect.py                  # generate a week of synthetic logs, detect, evaluate
    python detect.py --sensitivity 3  # 1 (quiet) … 5 (paranoid)

All IPs come from documentation-only ranges (RFC 5737); all users are fictional.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
SITE_DATA = HERE.parents[1] / "docs" / "demos" / "data"

CITIES = {  # name: (country, lat, lon, utc_offset_hours)
    "Denver": ("US", 39.74, -104.99, -6), "Chicago": ("US", 41.88, -87.63, -5), "Austin": ("US", 30.27, -97.74, -5),
    "London": ("GB", 51.51, -0.13, 1), "Bucharest": ("RO", 44.43, 26.10, 3), "Singapore": ("SG", 1.35, 103.82, 8),
    "Sao Paulo": ("BR", -23.55, -46.63, -3),
}
START = datetime(2026, 9, 28, 0, 0)

# Detection thresholds by sensitivity level (1 = fewest alerts … 5 = most)
LEVELS = {
    1: {"bf_fail": 30, "spray_users": 20, "kmh": 1500, "z": 4.5, "admin_hours": (5, 23)},
    2: {"bf_fail": 20, "spray_users": 15, "kmh": 1200, "z": 4.0, "admin_hours": (6, 22)},
    3: {"bf_fail": 10, "spray_users": 10, "kmh": 900, "z": 3.5, "admin_hours": (6, 21)},
    4: {"bf_fail": 6, "spray_users": 6, "kmh": 600, "z": 2.8, "admin_hours": (7, 20)},
    5: {"bf_fail": 4, "spray_users": 4, "kmh": 400, "z": 2.2, "admin_hours": (7, 19)},
}
ATTACK = {
    "Brute force": "T1110.001 Password Guessing", "Password spraying": "T1110.003 Password Spraying",
    "Impossible travel": "T1078 Valid Accounts", "Off-hours admin login": "T1078 Valid Accounts",
    "Data exfiltration spike": "T1567 Exfiltration Over Web Service", "First login from new country": "T1078 Valid Accounts",
}


def km(a: str, b: str) -> float:
    (_, la1, lo1, _), (_, la2, lo2, _) = CITIES[a], CITIES[b]
    p1, p2, dp, dl = map(math.radians, (la1, la2, la2 - la1, lo2 - lo1))
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def generate(seed: int = 11) -> list[dict]:
    rng = random.Random(seed)
    users = [f"user{i:02d}" for i in range(1, 41)] + ["admin.ops", "admin.db"]
    home = {u: rng.choice(["Denver", "Denver", "Chicago", "Austin"]) for u in users}
    ip_of = {u: f"198.51.100.{i + 10}" for i, u in enumerate(users)}
    ev = []

    def add(t, user, city, ok, mb=0.0, ip=None, incident=None):
        ev.append({"t": t.strftime("%Y-%m-%dT%H:%M"), "user": user, "ip": ip or ip_of[user], "city": city, "country": CITIES[city][0],
                   "ok": ok, "mb_out": round(mb, 1), "admin": user.startswith("admin"), "incident": incident})

    for day in range(7):
        if day in (5, 6):   # weekend: light activity
            active = rng.sample(users, 8)
        else:
            active = users
        for u in active:
            for _ in range(rng.randint(1, 4)):
                local_hour = rng.uniform(8, 18)
                t = START + timedelta(days=day, hours=local_hour - CITIES[home[u]][3])
                if rng.random() < 0.06:
                    add(t - timedelta(minutes=1), u, home[u], False)          # typo
                add(t, u, home[u], True, rng.lognormvariate(3.0, 0.6))

    # --- injected incidents (ground truth) ---
    t0 = START + timedelta(days=2, hours=9)                          # 1. brute force, then a hit
    for i in range(45):
        add(t0 + timedelta(seconds=12 * i), rng.choice(users[:6]), "Bucharest", False, ip="203.0.113.50", incident="Brute force")
    add(t0 + timedelta(minutes=10), users[3], "Bucharest", True, 35, ip="203.0.113.50", incident="Brute force")
    t1 = START + timedelta(days=3, hours=14)                         # 2. password spraying
    for i, u in enumerate(rng.sample(users, 24)):
        add(t1 + timedelta(minutes=2 * i), u, "Singapore", False, ip="203.0.113.77", incident="Password spraying")
    victim = "user17"                                                # 3. impossible travel
    t2 = START + timedelta(days=4, hours=16)
    add(t2, victim, home[victim], True, 18)
    add(t2 + timedelta(minutes=35), victim, "Sao Paulo", True, 22, ip="192.0.2.140", incident="Impossible travel")
    t3 = START + timedelta(days=5, hours=9, minutes=12)              # 4. admin at 03:12 Denver time from abroad
    add(t3, "admin.db", "London", True, 40, ip="192.0.2.66", incident="Off-hours admin login")
    t4 = START + timedelta(days=1, hours=20)                         # 5. exfiltration
    add(t4, "user08", home["user08"], True, 4800, incident="Data exfiltration spike")
    # benign look-alike: real business travel (should be low severity, not an incident)
    add(START + timedelta(days=3, hours=10), "user22", "London", True, 25, ip="192.0.2.20")
    ev.sort(key=lambda e: e["t"])
    return ev


def detect(events: list[dict], level: int = 3) -> list[dict]:
    L = LEVELS[level]
    ts = lambda e: datetime.fromisoformat(e["t"])  # noqa: E731
    alerts = []

    def alert(kind, sev, events_, why):
        alerts.append({"type": kind, "severity": sev, "attack": ATTACK[kind], "t": events_[0]["t"], "user": events_[0]["user"],
                       "ip": events_[0]["ip"], "why": why, "incident": next((e["incident"] for e in events_ if e["incident"]), None)})

    # failures grouped per IP in 60-minute windows
    by_ip = defaultdict(list)
    for e in events:
        if not e["ok"]:
            by_ip[e["ip"]].append(e)
    for ip, fails in by_ip.items():
        i = 0
        while i < len(fails):
            win = [f for f in fails[i:] if ts(f) - ts(fails[i]) <= timedelta(minutes=60)]
            users = {f["user"] for f in win}
            if len(users) >= L["spray_users"] and len(win) <= len(users) * 1.5:
                alert("Password spraying", "high", win, f"{len(win)} failed logins across {len(users)} different accounts from {ip} in one hour")
                i += len(win); continue
            short = [f for f in win if ts(f) - ts(win[0]) <= timedelta(minutes=15)]
            if len(short) >= L["bf_fail"]:
                follow = [e for e in events if e["ok"] and e["ip"] == ip and timedelta(0) <= ts(e) - ts(short[-1]) <= timedelta(minutes=30)]
                why = f"{len(short)} failed logins from {ip} in 15 min" + (f", then a SUCCESSFUL login as {follow[0]['user']}" if follow else "")
                alert("Brute force", "critical" if follow else "high", short + follow, why)
                i += len(win); continue
            i += 1

    # per-user checks on successful logins
    by_user = defaultdict(list)
    for e in events:
        if e["ok"]:
            by_user[e["user"]].append(e)
    for u, ok in by_user.items():
        seen_countries = set()
        mbs = [math.log1p(e["mb_out"]) for e in ok]
        for i, e in enumerate(ok):
            others = mbs[:i] + mbs[i + 1:]          # baseline = this user's OTHER sessions
            mu = sum(others) / max(len(others), 1)
            sd = max((sum((m - mu) ** 2 for m in others) / max(len(others), 1)) ** 0.5, 0.3)
            if i > 0:
                prev = ok[i - 1]
                hours = max((ts(e) - ts(prev)).total_seconds() / 3600, 1 / 60)
                dist = km(prev["city"], e["city"])
                if dist > 300 and dist / hours > L["kmh"]:
                    alert("Impossible travel", "high", [e, prev], f"{prev['city']} → {e['city']} ({dist:,.0f} km) in {hours * 60:.0f} min = {dist / hours:,.0f} km/h")
            z = (math.log1p(e["mb_out"]) - mu) / sd
            if z > L["z"]:
                alert("Data exfiltration spike", "high", [e], f"{e['mb_out']:,.0f} MB sent vs. this user's normal ~{math.expm1(mu):,.0f} MB (z = {z:.1f})")
            local = (ts(e) + timedelta(hours=CITIES["Denver"][3])).hour
            lo, hi = L["admin_hours"]
            if e["admin"] and not (lo <= local < hi):
                alert("Off-hours admin login", "critical", [e], f"Admin login at {local:02d}:{ts(e).minute:02d} Denver time from {e['city']}")
            if seen_countries and e["country"] not in seen_countries and level >= 2:
                alert("First login from new country", "low", [e], f"First login from {e['country']} for {u}")
            seen_countries.add(e["country"])
    return sorted(alerts, key=lambda a: a["t"])


def evaluate(events, alerts) -> dict:
    incidents = {e["incident"] for e in events if e["incident"]}
    caught = {a["incident"] for a in alerts if a["incident"]}
    fp = [a for a in alerts if not a["incident"]]
    return {"incidents": len(incidents), "caught": len(caught & incidents), "alerts": len(alerts), "false_positives": len(fp),
            "missed": sorted(incidents - caught)}


def export(events) -> None:
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    payload = {"events": events, "cities": CITIES, "levels": LEVELS, "attack": ATTACK}
    (SITE_DATA / "auth_logs.json").write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sensitivity", type=int, default=3, choices=range(1, 6))
    a = ap.parse_args()
    events = generate()
    export(events)
    print(f"{len(events):,} login events over 7 days, {len({e['user'] for e in events})} accounts\n")
    for lvl in range(1, 6):
        r = evaluate(events, detect(events, lvl))
        print(f"sensitivity {lvl}: caught {r['caught']}/{r['incidents']} incidents · {r['alerts']} alerts · {r['false_positives']} false positives"
              + (f" · missed {r['missed']}" if r["missed"] else ""))
    print(f"\nAlerts at sensitivity {a.sensitivity}:")
    for al in detect(events, a.sensitivity):
        print(f"  [{al['severity']:<8}] {al['t']}  {al['type']:<28} {al['why']}")
