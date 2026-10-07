"""Risk-based vulnerability prioritization: fix what attackers will actually use, not just the highest CVSS.

    python prioritize.py               # compare CVSS-only vs risk-based ordering
    python prioritize.py --budget 15   # how many fixes the team can ship this sprint

Risk = likelihood of exploitation × business impact, where likelihood combines an EPSS-style exploit probability,
whether the vulnerability is on a known-exploited list (like CISA KEV), and internet exposure.
All findings, scores and assets are synthetic.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

HERE = Path(__file__).parent
SITE_DATA = HERE.parents[1] / "docs" / "demos" / "data"

WEB = ["Remote code execution in web framework", "SQL injection in reporting module", "Cross-site scripting in admin panel",
       "Server-side request forgery in web app", "Missing security headers", "Outdated TLS configuration", "Deserialization flaw in Java library"]
# Typical CVSS base by weakness type; only serious, weaponizable classes can be on a known-exploited list
SEVERITY = {"Remote code execution in web framework": 9.0, "Remote code execution in mail server": 9.3, "SQL injection in reporting module": 8.4,
            "Authentication bypass in VPN appliance": 9.4, "Deserialization flaw in Java library": 8.8, "Privilege escalation in OS kernel": 7.6,
            "Default credentials on device": 8.0, "Authentication relay weakness": 8.1, "Server-side request forgery in web app": 7.4,
            "Memory corruption in image library": 7.8, "Unpatched browser on workstation": 7.5, "Cross-site scripting in admin panel": 5.6,
            "Information disclosure in API": 5.3, "Denial of service in DNS service": 6.2, "Outdated firmware": 6.0,
            "Outdated TLS configuration": 4.3, "Missing security headers": 3.1}
WEAPONIZABLE = {k for k, v in SEVERITY.items() if v >= 7.4}

ASSETS = [  # (name, business criticality 1-5, internet-facing, plausible weaknesses)
    ("Customer web portal", 5, True, WEB), ("Payments API", 5, True, WEB + ["Information disclosure in API"]),
    ("Marketing website", 2, True, WEB), ("VPN gateway", 5, True, ["Authentication bypass in VPN appliance", "Outdated TLS configuration", "Default credentials on device"]),
    ("Email server", 4, True, ["Remote code execution in mail server", "Outdated TLS configuration", "Privilege escalation in OS kernel"]),
    ("HR system", 4, False, WEB), ("Internal wiki", 2, False, WEB),
    ("Build server", 4, False, ["Deserialization flaw in Java library", "Privilege escalation in OS kernel", "Default credentials on device"]),
    ("Domain controller", 5, False, ["Privilege escalation in OS kernel", "Authentication relay weakness", "Denial of service in DNS service"]),
    ("Dev laptop fleet", 3, False, ["Unpatched browser on workstation", "Memory corruption in image library", "Privilege escalation in OS kernel"]),
    ("Printer network", 1, False, ["Default credentials on device", "Outdated firmware"]),
    ("Data warehouse", 4, False, ["SQL injection in reporting module", "Information disclosure in API", "Privilege escalation in OS kernel"]),
]


def build_findings(n: int = 60, seed: int = 21) -> list[dict]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        name, crit, internet, weak = rng.choice(ASSETS)
        title = rng.choice(weak)
        kev = title in WEAPONIZABLE and rng.random() < 0.15
        epss = rng.betavariate(0.4, 6) * (1 if title in WEAPONIZABLE else 0.3)          # most near 0, a few high
        epss = round(min(epss + (0.45 if kev else 0), 0.97), 3)
        cvss = round(min(10, max(2.0, rng.gauss(SEVERITY[title], 0.7))), 1)
        out.append({"id": f"VULN-{i + 1:03d}", "title": title, "asset": name, "criticality": crit,
                    "internet_facing": internet, "cvss": cvss, "epss": epss, "kev": kev, "fix_hours": rng.choice([1, 2, 4, 8, 16])})
    return out


def likelihood(f: dict, use_epss=True, use_kev=True, use_exposure=True) -> float:
    p = f["epss"] if use_epss else 0.1
    if use_kev and f["kev"]:
        p = max(p, 0.9)
    if use_exposure:
        p = min(1.0, p * (1.5 if f["internet_facing"] else 0.7))
    return p


def impact(f: dict, use_criticality=True) -> float:
    return f["cvss"] / 10 * ((f["criticality"] / 5) if use_criticality else 1)


def true_risk(f: dict) -> float:
    """The yardstick: full model (what an attacker's odds really look like in this simulation)."""
    return likelihood(f) * impact(f)


def rank(findings, strategy: str, **opts) -> list[dict]:
    if strategy == "cvss":
        key = lambda f: (-f["cvss"], f["id"])  # noqa: E731
    else:
        key = lambda f: (-(likelihood(f, opts.get("epss", True), opts.get("kev", True), opts.get("exposure", True))  # noqa: E731
                           * impact(f, opts.get("criticality", True))), f["id"])
    return sorted(findings, key=key)


def outcome(findings, order, budget: int) -> dict:
    fixed = order[:budget]
    total = sum(true_risk(f) for f in findings)
    kev_total = sum(f["kev"] for f in findings)
    return {"risk_removed": sum(true_risk(f) for f in fixed) / total,
            "kev_fixed": sum(f["kev"] for f in fixed), "kev_total": kev_total,
            "hours": sum(f["fix_hours"] for f in fixed)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=10)
    a = ap.parse_args()
    fs = build_findings()
    print(f"{len(fs)} open findings · {sum(f['cvss'] >= 7 for f in fs)} rated High/Critical by CVSS · "
          f"{sum(f['kev'] for f in fs)} on the known-exploited list\n")
    print(f"If the team can fix {a.budget} this sprint:")
    for label, strat in [("CVSS only (highest score first)", "cvss"), ("Risk-based (likelihood × impact)", "risk")]:
        o = outcome(fs, rank(fs, strat), a.budget)
        print(f"  {label:<36} removes {o['risk_removed']:.0%} of total risk · fixes {o['kev_fixed']}/{o['kev_total']} known-exploited")
    print("\nBudget needed to remove 80% of risk:")
    for label, strat in [("CVSS only", "cvss"), ("Risk-based", "risk")]:
        order = rank(fs, strat)
        k = next(k for k in range(1, len(fs) + 1) if outcome(fs, order, k)["risk_removed"] >= 0.8)
        print(f"  {label:<12} {k} fixes")
    print("\nTop 10, risk-based:")
    for f in rank(fs, "risk")[:10]:
        print(f"  {f['id']}  risk {true_risk(f):.2f}  CVSS {f['cvss']:>4}  EPSS {f['epss']:.0%}{'  KEV' if f['kev'] else '     '}  {f['asset']}: {f['title']}")
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    (SITE_DATA / "findings.json").write_text(json.dumps(fs), encoding="utf-8")
