# 03 · Login Anomaly Detection

**▶ [Try it live](https://za1d3v.github.io/Cyber-AI/demos/logs.html)** · MITRE ATT&CK T1110.001, T1110.003, T1078, T1567

## The client problem
A 42-person company uses cloud sign-in (Microsoft 365 / Okta style) but nobody reviews the logs. They have no
SOC and no SIEM budget. They want to know: *would we even notice a credential attack?*

## Approach
A week of sign-in logs, with **5 attacks injected** as ground truth:

| Attack | How it's detected | ATT&CK |
|---|---|---|
| Brute force, then a successful login | ≥ N failures from one IP in 15 min, plus a success afterwards → critical | T1110.001 |
| Password spraying | Failures across many *different* accounts from one IP in an hour | T1110.003 |
| Impossible travel | Two logins farther apart than any plane could fly in the time between | T1078 |
| Off-hours admin login from abroad | Admin sign-in outside business hours | T1078 |
| Data exfiltration | Session upload volume vs. **that user's own** baseline (z-score, leave-one-out) | T1567 |

All rules are explainable. Every alert says *why* in plain English and maps to MITRE ATT&CK.

## Results: the sensitivity tradeoff

| Sensitivity | Attacks caught | Alerts | False positives |
|---|---|---|---|
| 1 (quiet) | 5/5 | 7 | 1 |
| 3 (default) | 5/5 | 14 | 4 |
| 5 (paranoid) | 5/5 | 30 | 18 |

False positives come from a real business trip and ordinary large uploads. That's typical in production: context
(travel calendars, VPN allow-lists, approved file-sharing) removes far more noise than a fancier model.

## Run it
```bash
python projects/03-log-anomaly-detection/detect.py
python projects/03-log-anomaly-detection/detect.py --sensitivity 5
```

## What I'd do in production
- Ingest real identity-provider logs (Entra ID, Okta, Google Workspace) and enrich IPs with geolocation and reputation
- Add an unsupervised model (e.g. Isolation Forest) for patterns no rule anticipates, keeping rules for explainability
- Send alerts to Slack/Teams with one-click "lock account / it was me" responses
- Re-tune monthly using analyst feedback on false positives

> All data is synthetic. IP addresses come from documentation-only ranges (RFC 5737) and all users are fictional.
