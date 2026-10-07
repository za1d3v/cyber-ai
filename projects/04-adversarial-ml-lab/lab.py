"""Adversarial ML lab: attack a spam/scam filter, then harden it.

  1. Evasion: an attacker rewrites a scam message (l33t-speak, synonyms) until the filter lets it through.
  2. Defenses: input normalization and adversarial training.
  3. Poisoning: an attacker who can tamper with training labels degrades the model; data sanitization helps.

    python lab.py

Toy-scale and fully synthetic, for teaching how ML systems fail. Maps to OWASP LLM04 (Data and Model Poisoning)
and the evasion/poisoning tactics catalogued in MITRE ATLAS.
"""
from __future__ import annotations

import json
import math
import random
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
SITE_DATA = HERE.parents[1] / "docs" / "demos" / "data"

LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}
UNLEET = {v: k for k, v in LEET.items()}
PAD_WORDS = ["meeting", "thanks", "agenda", "tomorrow", "report", "slides", "lunch", "dinner"]  # attacker's guess at "innocent" words
SYNONYMS = {"free": "complimentary", "click": "tap", "winner": "selected", "prize": "reward", "urgent": "time-sensitive",
            "verify": "validate", "account": "profile", "claim": "collect", "cash": "funds", "password": "passcode",
            "won": "received", "offer": "deal", "suspended": "paused", "congratulations": "great news"}


# ---------------- data ----------------
def build_dataset(seed: int = 3) -> list[dict]:
    rng = random.Random(seed)
    spam_t = [
        "congratulations you won a {p} claim your {p2} now click {l}",
        "urgent your account is suspended verify your password at {l}",
        "you are a winner claim your free {p} today click {l}",
        "free cash offer for you click {l} to claim",
        "final notice verify your account now or it will be suspended {l}",
        "claim your free {p} winner selected text yes to {n}",
        "urgent offer free {p} for the first 100 winners click {l}",
        "your package is on hold pay the fee to claim it at {l}",
    ]
    ham_t = [
        "are you free for lunch {d}", "can you send me the slides before the meeting", "running ten minutes late see you soon",
        "click the link i sent for the agenda", "happy birthday hope you have a great day", "the {d} meeting moved to 3pm",
        "did you finish the report", "thanks for dinner last night", "can you pick up milk on the way home",
        "your verification code is {n} do not share it", "reminder dentist appointment {d} at 9am",
        "we won the game last night", "the account review is on the agenda for {d}", "let me know if the offer letter looks ok",
    ]
    fill = lambda t: t.format(p=rng.choice(["prize", "gift card", "reward", "iphone", "vacation"]), p2=rng.choice(["prize", "reward", "cash"]),  # noqa: E731
                              l=rng.choice(["bit.ly/x9", "win-now.top", "claim-gift.xyz", "secure-acct.info"]),
                              n=rng.choice(["80082", "61234", "44871"]), d=rng.choice(["monday", "tomorrow", "friday", "thursday"]))
    rows = [{"text": fill(rng.choice(spam_t)), "label": 1} for _ in range(200)] + [{"text": fill(rng.choice(ham_t)), "label": 0} for _ in range(200)]
    rng.shuffle(rows)
    return rows


def split(rows):
    return [r for i, r in enumerate(rows) if i % 5 != 4], [r for i, r in enumerate(rows) if i % 5 == 4]


def tokens(text: str, normalize: bool = False) -> list[str]:
    t = text.lower()
    if normalize:
        t = re.sub(r"(?<=\w)[.\-_*](?=\w)", "", t)              # p.a.s.s → pass
        t = "".join(UNLEET.get(c, c) for c in t)                # v3r1fy → verify
    return re.findall(r"[a-z0-9$]+(?:-[a-z0-9]+)*", t)


# ---------------- model ----------------
class NaiveBayes:
    def __init__(self, normalize: bool = False):
        self.normalize = normalize

    def fit(self, rows):
        self.counts = [Counter(), Counter()]
        self.docs = [0, 0]
        for r in rows:
            self.docs[r["label"]] += 1
            self.counts[r["label"]].update(tokens(r["text"], self.normalize))
        self.vocab = set(self.counts[0]) | set(self.counts[1])
        self.tot = [sum(c.values()) for c in self.counts]
        return self

    def word_score(self, w: str) -> float:
        """log P(w|spam) - log P(w|ham); >0 means the word pushes toward spam."""
        V = len(self.vocab)
        return math.log((self.counts[1][w] + 1) / (self.tot[1] + V)) - math.log((self.counts[0][w] + 1) / (self.tot[0] + V))

    def p_spam(self, text: str) -> float:
        z = math.log((self.docs[1] + 1) / (self.docs[0] + 1))
        z += sum(self.word_score(w) for w in tokens(text, self.normalize) if w in self.vocab)
        return 1 / (1 + math.exp(-max(min(z, 50), -50)))

    def accuracy(self, rows) -> float:
        return sum((self.p_spam(r["text"]) >= 0.5) == r["label"] for r in rows) / len(rows)


# ---------------- attacks ----------------
def obfuscate(word: str, mode: str) -> str:
    if mode == "leet":
        return "".join(LEET.get(c, c) for c in word)
    return SYNONYMS.get(word, word)


MODES = ("leet", "synonym", "pad")


def evade(model: NaiveBayes, text: str, budget: int = 6, modes=MODES) -> tuple[str, list[str], bool]:
    """Greedy attack: each step makes the single edit that lowers the spam score most, until the filter says ham.
    Edits: l33t-speak a word, swap in a synonym, or append an innocent-looking word ("good-word attack")."""
    words, steps = text.split(), []
    for _ in range(budget):
        if model.p_spam(" ".join(words)) < 0.5:
            break
        best = None
        cands = []
        for i, w in enumerate(words):
            for m in modes:
                if m == "pad":
                    continue
                nw = obfuscate(w, m)
                if nw != w:
                    cands.append((words[:i] + [nw] + words[i + 1:], f"{w} → {nw}"))
        if "pad" in modes:
            cands += [(words + [pw], f"+ '{pw}'") for pw in PAD_WORDS]
        for cand, label in cands:
            p = model.p_spam(" ".join(cand))
            if best is None or p < best[0]:
                best = (p, cand, label)
        if best is None:
            break
        _, words, label = best
        steps.append(label)
    final = " ".join(words)
    return final, steps, model.p_spam(final) < 0.5


def evasion_rate(model, test, **kw) -> float:
    spam = [r for r in test if r["label"] == 1 and model.p_spam(r["text"]) >= 0.5]
    return sum(evade(model, r["text"], **kw)[2] for r in spam) / max(len(spam), 1)


def augment(rows, rng: random.Random, copies: int = 2):
    """Adversarial training: add attacked copies of spam (synonyms + padding) to the training set."""
    extra = []
    for r in rows:
        if r["label"] == 1:
            for _ in range(copies):
                ws = [obfuscate(w, "synonym") if rng.random() < 0.5 else w for w in r["text"].split()]
                ws += rng.sample(PAD_WORDS, rng.randint(0, 3))
                extra.append({"text": " ".join(ws), "label": 1})
    return rows + extra


# ---------------- poisoning ----------------
def poison_order(rows, seed: int = 0) -> list[int]:
    """The order in which the attacker corrupts spam examples (so 40% poisoned ⊂ 60% poisoned)."""
    idx = [i for i, r in enumerate(rows) if r["label"] == 1]
    random.Random(seed).shuffle(idx)
    return idx


def poison(rows, frac: float, seed: int = 0):
    """Attacker flips the label on a fraction of SPAM training examples to 'ham'."""
    order = poison_order(rows, seed)
    flip = set(order[: int(len(order) * frac)])
    return [{**r, "label": 0} if i in flip else r for i, r in enumerate(rows)]


GOLDEN = 30   # size of a small, human-verified "golden" set the attacker can't touch


def sanitize(rows, golden):
    """Drop training examples whose label disagrees with a reference model trained only on trusted, verified data."""
    ref = NaiveBayes().fit(golden)
    return golden + [r for r in rows if (ref.p_spam(r["text"]) >= 0.5) == r["label"]]


def poisoning_curve(train, test, sanitized: bool = False):
    golden, pool = train[:GOLDEN], train[GOLDEN:]
    out = []
    for pct in (0, 20, 40, 60, 70, 80, 90):
        # undefended: attacker can corrupt any training label; defended: the golden set is protected
        tr = sanitize(poison(pool, pct / 100), golden) if sanitized else poison(train, pct / 100)
        m = NaiveBayes().fit(tr)
        spam = [r for r in test if r["label"] == 1]
        out.append((pct, sum(m.p_spam(r["text"]) >= 0.5 for r in spam) / len(spam)))
    return out


if __name__ == "__main__":
    rows = build_dataset()
    train, test = split(rows)
    rng = random.Random(1)
    base = NaiveBayes().fit(train)
    norm = NaiveBayes(normalize=True).fit(train)
    hard = NaiveBayes(normalize=True).fit(augment(train, rng))
    print(f"Clean accuracy: baseline {base.accuracy(test):.0%} · normalized {norm.accuracy(test):.0%} · hardened {hard.accuracy(test):.0%}\n")
    print("Evasion success (≤6 edits): share of scam messages that get through:")
    for name, m in [("Baseline filter", base), ("+ normalization", norm), ("+ normalization + adversarial training", hard)]:
        print(f"  {name:<40} l33t only {evasion_rate(m, test, modes=('leet',)):>4.0%} · all tricks {evasion_rate(m, test):>4.0%}")
    ex = next(r["text"] for r in test if r["label"] == 1)
    adv, steps, ok = evade(base, ex)
    print(f"\nExample: '{ex}'\n  → '{adv}'  ({'; '.join(steps)}) {'EVADED' if ok else 'blocked'}")
    print("\nPoisoning (attacker flips X% of spam training labels to 'ham') → share of scams still caught:")
    print(f"  (defense: filter training data with a model trained on {GOLDEN} human-verified examples)")
    for (pct, a), (_, s) in zip(poisoning_curve(train, test), poisoning_curve(train, test, sanitized=True)):
        print(f"  {pct:>3}% poisoned: {a:.0%}   with sanitization: {s:.0%}")
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    extra = augment(train, random.Random(1))[len(train):]   # exported so the browser trains the identical hardened model
    (SITE_DATA / "advml.json").write_text(json.dumps({"rows": rows, "leet": LEET, "synonyms": SYNONYMS, "pad": PAD_WORDS,
                                                      "augment": extra, "poison_order": poison_order(train), "poison_order_pool": poison_order(train[GOLDEN:]), "golden": GOLDEN}), encoding="utf-8")
