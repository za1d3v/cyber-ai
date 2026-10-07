# 02 · Explainable Phishing Detector

**▶ [Try it live](https://za1d3v.github.io/cyber-ai/demos/phishing.html)**

## The client problem
A 300-person company's security team spends hours each day on emails employees report with the "Report phishing" button.
Most are harmless, and the real phish wait in the queue. Their email gateway gives a score but never says *why*,
so analysts can't trust it and employees don't learn anything.

## Approach
1. **11 human-readable signals** per email: lookalike sender domain, display-name spoofing, Reply-To mismatch,
   urgency, credential requests, link text ≠ real destination, odd link domains, shorteners/IP links, risky attachments,
   payment requests, generic greetings.
2. **Logistic regression** learns how much each signal matters. Unlike a black box, every verdict lists its reasons.
3. **Adjustable threshold** so the client can choose between catching more phish and raising more false alarms.

The Python script exports its trained weights to the live demo, so both give **identical scores**.

## Results (300 synthetic emails: 240 train, 60 held out)

| Accuracy | Precision | Recall | False alarms | Phish missed |
|---|---|---|---|---|
| 93% | 100% | 87% | 0 | 4 |

**All four misses are business email compromise (BEC):** a payment-change request sent from a *real, hacked*
vendor mailbox. Nothing technical looks wrong. That's the most important finding to give a client: some attacks
need a **process** control (phone-verify every bank-detail change), not a better model.

The data includes realistic hard cases: genuine IT alerts with urgent wording, marketing with shortened links and
"last chance" language, and real vendor payment reminders.

## Run it
```bash
python projects/02-phishing-detector/phishing.py
```

## What I'd do in production
- Train on the client's own reported-phish history; add header checks (SPF/DKIM/DMARC results) as signals
- Combine with a text model or LLM for wording-based cues, while keeping the explainable signals as the "why"
- Route by score: auto-quarantine, analyst review, or auto-close with a thank-you note to the reporter
- Feed the "why" into security-awareness training using the company's real examples
