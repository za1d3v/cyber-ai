# Responsible use

This repository demonstrates **defensive and authorized** security work.

- **Authorization first.** Only run these tools against systems you own or have explicit written permission to test,
  under agreed rules of engagement.
- **Safe by design.** The LLM red-team probes check for a planted *canary* string and never request harmful content.
  Purple-team tests are benign emulations (test accounts, lab hosts, SOC informed). No exploit code is included.
- **Synthetic data only.** All emails, logs, users, organizations and vulnerability findings are generated. IP addresses
  come from documentation-only ranges (RFC 5737). Organization names are fictional.
- **Report, don't exploit.** If you find a real vulnerability with techniques like these, follow coordinated disclosure.

Questions: zaidev92@gmail.com
