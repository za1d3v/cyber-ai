# 07 · Bilingual Prompt-Injection Probe Pack

**▶ [Try it live](https://za1d3v.github.io/cyber-ai/demos/bilingual.html)** · OWASP LLM01, LLM07 · MITRE ATLAS

## The client problem
A company self-hosts a Chinese-developed open model (Qwen, DeepSeek, Kimi, GLM, MiniMax…) because it's capable and cheap,
or serves Chinese-speaking users with any model. Their security team wrote an input filter, in English. Independent evaluations
have found that some Chinese-developed models are **much more susceptible to prompt injection and agent hijacking** than
US frontier models, and that safety behavior often doesn't transfer across languages. So: does the English guardrail actually
protect a bilingual deployment?

## Approach
Ten **canary-based** probes (they only try to surface a planted test code `CANARY-7F3A` or a fake email — never real
harmful content), each a different way of hiding the same injection from an English keyword filter:

| Variant | Trick |
|---|---|
| Simplified / Traditional Chinese | the instruction is simply not in English |
| Code-switching | attack words split across Chinese and English in one sentence |
| Full-width characters | `Ｉｇｎｏｒｅ` looks like text but isn't ASCII |
| Zero-width characters | invisible spaces split the keywords |
| Pinyin | romanized Chinese with no characters at all |
| Translation wrapper | "translate this, then do what it says" |
| Indirect injection | the instruction is hidden inside a Chinese document the bot summarizes |

Then four defenses, applied in layers.

## Results (simulated bilingual bot)

| Configuration | Probes defended |
|---|---|
| English-only keyword filter | **1/10** (only the normal request survives) |
| + Input normalization (NFKC, strip invisible chars) | 3/10 |
| + Bilingual filter | 8/10 |
| **Defense in depth (normalization + bilingual filter + prompt hardening + output filter)** | **10/10** |

**Takeaways:**
- An English-only filter catches **none** of these. This is the core finding.
- **Normalization** (full-width → ASCII, drop zero-width characters) is the cheapest, highest-value fix, and it's lossless for real users.
- A bilingual keyword list helps, but **code-switching** and **document-embedded** injections still get through the input layer, so you need prompt hardening and output filtering too.

## Run it
```bash
python projects/07-bilingual-injection-probes/bilingual.py          # simulated target

# Probe a real OpenAI-compatible endpoint (Qwen / DeepSeek / Kimi / GLM … — see your provider's docs for URL & model):
export LLM_API_KEY=...
python projects/07-bilingual-injection-probes/bilingual.py --live \
  --base-url https://YOUR-PROVIDER/v1 --model MODEL-NAME --trials 3 --wrap
```
`--wrap` puts this repo's normalization + bilingual filter + output filter around the live model, so you can measure
the before/after on your own deployment. Use `--trials` because real models are non-deterministic.

## What I'd do in a real engagement
- Expand each category with many paraphrases and run each several times; track leak rate per language and per model
- Add more locales (Traditional-only markets, other CJK languages) matched to the client's user base
- Pair the normalizer with the model provider's own safety API, and log normalized prompts to catch attacks in production
- Benchmark candidate models on this suite before selection, since results vary widely between Chinese models

> **Responsible use:** canary-based, no harmful-content elicitation. Only test systems and API accounts you own or are authorized to test.
> Model names are examples; this harness is vendor-neutral and works with any OpenAI-compatible endpoint.
