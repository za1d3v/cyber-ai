# 05 · MITRE ATT&CK Coverage Map → Purple-Team Plan

**▶ [Try it live](https://za1d3v.github.io/Cyber-AI/demos/attack.html)** · MITRE ATT&CK Enterprise

## The client problem
A mid-size company has an EDR, an email gateway and a SIEM. The board asks: *"Would we catch a real attacker?"*
The security team can list its tools, but not which attacker **behaviors** they actually detect, or what to fix first.

## Approach
1. **Map detections to ATT&CK.** 36 high-impact techniques across all 12 enterprise tactics, each marked
   *no detection / partial / detected & tested*, with its data source.
2. **Weight by prevalence.** Each technique gets a 1–5 weight for how often it shows up in real intrusions
   (illustrative here; in an engagement I'd use the client's threat intel and sector reports).
3. **Rank gaps** by prevalence × missing coverage.
4. **Generate a purple-team test plan.** For every gap, a *safe, pre-approved emulation* (test accounts, lab hosts, SOC informed)
   with pass criteria, so the red and blue teams can validate detections together.

## Results (fictional client)

| | Techniques covered | Prevalence-weighted |
|---|---|---|
| Client baseline | 26% | 28% |
| + Cyber-AI detections ([02 phishing](../02-phishing-detector), [03 login anomalies](../03-log-anomaly-detection)) | 32% | 36% |

**Top gaps:** Valid Accounts (T1078), Brute Force (T1110), Inhibit System Recovery (T1490), Exfiltration Over Web Service (T1567)
and MFA fatigue (T1621). The pattern is typical: endpoint coverage is decent because vendors sell it, while **identity and exfiltration**,
where most modern breaches happen, are blind spots.

## Run it
```bash
python projects/05-attack-coverage-map/attack_coverage.py
python projects/05-attack-coverage-map/attack_coverage.py --with-cyberai --plan purple_team_plan.md
```

## What I'd do in a real engagement
- Build the coverage map from the client's actual detection rules (SIEM/EDR exports), not a questionnaire
- Run the purple-team plan in sprints, re-score after each one, and report the trend to leadership
- Extend to MITRE ATLAS for AI/ML systems (see [01](../01-llm-redteam-harness) and [04](../04-adversarial-ml-lab))

> MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique IDs and names are from attack.mitre.org.
