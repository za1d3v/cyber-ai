# 04 · Adversarial ML Lab: evasion & data poisoning

**▶ [Try it live](https://za1d3v.github.io/Cyber-AI/demos/advml.html)** · OWASP LLM04 · MITRE ATLAS (evasion, poisoning)

## The client problem
A company uses an ML model to filter scam messages (the same applies to fraud, malware or content-moderation models).
It scores 100% on its test set. Leadership asks: *is it secure?* Accuracy on normal data says nothing about
how the model behaves when someone is actively trying to fool it.

## Approach
A small, transparent lab with a naive Bayes spam filter and two classic attacks:

**1. Evasion.** A greedy attacker makes up to 6 edits, each time picking whichever edit lowers the spam score most:
l33t-speak (`claim → cl41m`), synonyms (`prize → reward`), or appending innocent words (`+ meeting`, the "good-word attack").

**2. Poisoning.** The attacker corrupts training labels (e.g. via a compromised labeling vendor or abused feedback button), marking scams as "not spam".

## Results

| Filter | Normal accuracy | Scams evading (l33t only) | Scams evading (all tricks) |
|---|---|---|---|
| Baseline | 100% | 12.5% | **60%** |
| + Input normalization | 100% | 0% | **72.5%** ← worse! |
| + Normalization + adversarial training | 100% | 0% | **0%** |

Normalization alone backfires: blocked from l33t-speak, the attacker relies on synonyms and padding. That's the
arms race in one table. Adversarial training closes *these* gaps, but a new trick would need new training data.

| Spam labels poisoned | Scams caught (undefended) | With golden-set sanitization |
|---|---|---|
| 40% | 100% | 100% |
| 70% | 70% | 100% |
| 90% | 38% | 100% |

**Defense:** a small human-verified "golden" set (30 examples) trains a reference model that screens the rest of
the training data. Protecting where training data comes from matters as much as the model itself.

## Run it
```bash
python projects/04-adversarial-ml-lab/lab.py
```

## What I'd do in a real engagement
- Red-team the client's actual model with attacks matched to its inputs (text, images, tabular fraud features)
- Use MITRE ATLAS to threat-model the full ML pipeline: data collection, labeling, training, deployment, feedback loops
- Add adversarial examples to the regular retraining schedule, and track training-data provenance (who labeled what, when)

> Toy-scale and synthetic, built to teach how ML systems fail. The same ideas apply to production models at larger scale.
