# 06 · Risk-Based Vulnerability Prioritizer

**▶ [Try it live](https://za1d3v.github.io/Cyber-AI/demos/vulns.html)** · EPSS · CISA KEV · CVSS

## The client problem
The vulnerability scanner reports 60 open findings, and 43 are "High" or "Critical". The IT team can fix about 10 per sprint.
They've been working down the list by CVSS score and never catch up, while the vulnerabilities attackers actually use sit in the queue.

## Approach
Rank each finding by **risk = likelihood of exploitation × business impact**:

- **Likelihood:** an EPSS-style exploit probability, raised to ≥ 90% if the flaw is on a known-exploited list (like CISA KEV),
  and adjusted for internet exposure
- **Impact:** CVSS severity × the business criticality of the affected asset

Then compare the two fix orders on how much total risk each removes for the same effort.

## Results (synthetic environment)

| With 10 fixes this sprint | Sort by CVSS | Risk-based |
|---|---|---|
| Total risk removed | 34% | **89%** |
| Known-exploited flaws fixed | 2 of 5 | **5 of 5** |
| Fixes needed to remove 80% of risk | 29 | **7** |

The top risk-based items are a VPN authentication bypass and default credentials on the VPN, all known-exploited and internet-facing.
CVSS ranks some of them #29 and #34. A CVSS-10 SQL injection on an *internal* system still ranks high, but behind the exposed edge devices.

**Caveat:** risk is measured with the same likelihood × impact model, so this shows how differently the two orders spend effort, not
a ground-truth breach rate. The demo lets you switch each model input off to see which ones drive the result.

## Run it
```bash
python projects/06-vuln-prioritizer/prioritize.py
python projects/06-vuln-prioritizer/prioritize.py --budget 15
```

## What I'd do in a real engagement
- Pull live EPSS scores (FIRST) and the CISA KEV catalog daily; join with the scanner export and CMDB asset criticality
- Add compensating controls (WAF, segmentation, EDR) as likelihood reducers
- Publish SLAs by risk tier instead of by CVSS band, and track "risk removed per sprint" as the team's KPI

> All findings, scores and assets are synthetic. EPSS and KEV are the real data sources the model is built for.
