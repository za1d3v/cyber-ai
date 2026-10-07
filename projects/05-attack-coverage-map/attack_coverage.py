"""MITRE ATT&CK detection-coverage map → prioritized purple-team test plan.

    python attack_coverage.py                 # current coverage + top gaps
    python attack_coverage.py --with-cyberai  # add the detections from projects 02 and 03
    python attack_coverage.py --plan plan.md  # write a purple-team test plan for the top gaps
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

HERE = Path(__file__).parent
SITE_DATA = HERE.parents[1] / "docs" / "demos" / "data"
MATRIX = json.loads((HERE / "matrix.json").read_text(encoding="utf-8"))
CREDIT = {"none": 0.0, "partial": 0.5, "full": 1.0}


def techniques(with_cyberai: bool = False):
    for t in MATRIX["tactics"]:
        for tech in t["techniques"]:
            status = tech["status"]
            if with_cyberai and tech.get("cyberai") and status != "full":
                status = "partial" if status == "none" else "full"
            yield t, {**tech, "status": status}


def coverage(with_cyberai: bool = False) -> dict:
    rows = list(techniques(with_cyberai))
    weighted = sum(t["w"] * CREDIT[t["status"]] for _, t in rows) / sum(t["w"] for _, t in rows)
    plain = sum(CREDIT[t["status"]] for _, t in rows) / len(rows)
    per_tactic = {}
    for tac, t in rows:
        per_tactic.setdefault(tac["name"], []).append(CREDIT[t["status"]])
    return {"weighted": weighted, "plain": plain, "n": len(rows),
            "per_tactic": {k: sum(v) / len(v) for k, v in per_tactic.items()}}


def gaps(with_cyberai: bool = False, top: int = 8) -> list[dict]:
    """Risk-weighted gaps: prevalence × how much coverage is missing."""
    out = [{**t, "tactic": tac["name"], "gap": t["w"] * (1 - CREDIT[t["status"]])} for tac, t in techniques(with_cyberai)]
    return sorted([g for g in out if g["gap"] > 0], key=lambda g: (-g["gap"], g["id"]))[:top]


def plan(with_cyberai: bool = False, top: int = 8) -> str:
    lines = ["# Purple-team test plan", "", "Safe, pre-approved emulations to validate (or build) detections, in priority order.",
             "Run only in authorized environments, with test accounts and lab hosts, and with the SOC informed.", "",
             "| # | Technique | Tactic | Current | Test | Pass criteria |", "|---|---|---|---|---|---|"]
    for i, g in enumerate(gaps(with_cyberai, top), 1):
        lines.append(f"| {i} | {g['id']} {g['name']} | {g['tactic']} | {g['status']} | {g['test']} | Alert in SIEM within 15 min, triaged by on-call |")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-cyberai", action="store_true")
    ap.add_argument("--plan", metavar="FILE")
    a = ap.parse_args()
    for label, flag in [("Current", False), ("With Cyber-AI detections (projects 02 + 03)", True)]:
        c = coverage(flag)
        print(f"{label}: {c['plain']:.0%} of {c['n']} techniques covered · {c['weighted']:.0%} prevalence-weighted")
    c = coverage(a.with_cyberai)
    print("\nBy tactic:")
    for k, v in c["per_tactic"].items():
        print(f"  {k:<22} {'█' * round(v * 20):<20} {v:.0%}")
    print("\nTop gaps to test next (prevalence × missing coverage):")
    for g in gaps(a.with_cyberai):
        print(f"  {g['gap']:.1f}  {g['id']:<6} {g['name']:<45} ({g['tactic']}, {g['status']})")
    if a.plan:
        Path(a.plan).write_text(plan(a.with_cyberai), encoding="utf-8")
        print(f"\nWrote {a.plan}")
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "matrix.json", SITE_DATA / "attack_matrix.json")
