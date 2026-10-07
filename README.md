# Cyber-AI: AI for Security, Security for AI

> White-hat consulting portfolio by **Zitao Wang**: LLM red teaming, adversarial ML, detection engineering and risk-based prioritization.

**🌐 Live site & demos:** https://za1d3v.github.io/cyber-ai/
**📫 Contact:** zaidev92@gmail.com · [LinkedIn](https://www.linkedin.com/in/zitao-wang-08386130b/) · [AI/ML consulting portfolio](https://za1d3v.github.io/zitao-ai-portfolio/)

Seven demos that mirror real engagements. Each has runnable Python, a case-study README and a live in-browser version.
Everything runs offline on synthetic data. No API keys, no real targets (demo 07 can optionally probe a live endpoint you own).

| # | Project | Team | Frameworks | Live |
|---|---------|------|-----------|------|
| 01 | [**LLM Red-Team Harness**](projects/01-llm-redteam-harness): 10 safe probes, 5 defense layers | 🔴 Red | OWASP LLM01/02/05/06/07/10, ATLAS | [▶](https://za1d3v.github.io/cyber-ai/demos/redteam.html) |
| 02 | [**Explainable Phishing Detector**](projects/02-phishing-detector): 93% accuracy, every verdict explained | 🔵 Blue | ATT&CK T1566 | [▶](https://za1d3v.github.io/cyber-ai/demos/phishing.html) |
| 03 | [**Login Anomaly Detection**](projects/03-log-anomaly-detection): brute force, spraying, impossible travel, exfil | 🔵 Blue | ATT&CK T1110, T1078, T1567 | [▶](https://za1d3v.github.io/cyber-ai/demos/logs.html) |
| 04 | [**Adversarial ML Lab**](projects/04-adversarial-ml-lab): evasion & data poisoning, with defenses | 🔴 Red | OWASP LLM04, ATLAS | [▶](https://za1d3v.github.io/cyber-ai/demos/advml.html) |
| 05 | [**ATT&CK Coverage Map**](projects/05-attack-coverage-map): gaps → purple-team test plan | 🟣 Purple | ATT&CK (36 techniques) | [▶](https://za1d3v.github.io/cyber-ai/demos/attack.html) |
| 06 | [**Risk-Based Vuln Prioritizer**](projects/06-vuln-prioritizer): 89% of risk removed vs 34% by CVSS | 🟣 Purple | EPSS, KEV, CVSS | [▶](https://za1d3v.github.io/cyber-ai/demos/vulns.html) |
| 07 | [**Bilingual Prompt-Injection Probes**](projects/07-bilingual-injection-probes): Chinese & character-trick injections vs. English-only filters | 🔴 Red | OWASP LLM01/07, ATLAS | [▶](https://za1d3v.github.io/cyber-ai/demos/bilingual.html) |

See the full [framework map](https://za1d3v.github.io/cyber-ai/demos/frameworks.html) (OWASP LLM Top 10, MITRE ATLAS, MITRE ATT&CK, NIST CSF 2.0).

## Quick start
```bash
git clone https://github.com/za1d3v/Cyber-AI.git && cd Cyber-AI
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python projects/01-llm-redteam-harness/redteam.py
python projects/02-phishing-detector/phishing.py
python projects/03-log-anomaly-detection/detect.py
python projects/04-adversarial-ml-lab/lab.py
python projects/05-attack-coverage-map/attack_coverage.py
python projects/06-vuln-prioritizer/prioritize.py
python projects/07-bilingual-injection-probes/bilingual.py
pytest
```

## Layout
```
docs/              → website + live demos (GitHub Pages)
docs/demos/data/   → data exported by the Python scripts, so browser and Python results match
projects/          → one folder per demo, each README is a case study
tests/             → tests run on every push
```

## Responsible use
This is a **white-hat** portfolio. All data is synthetic, targets are simulated, IP addresses come from documentation-only
ranges, and no exploit code is included. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

## License
MIT. See [LICENSE](LICENSE). MITRE ATT&CK® and ATLAS™ are trademarks of The MITRE Corporation.
