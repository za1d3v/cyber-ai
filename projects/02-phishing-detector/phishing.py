"""Explainable phishing email detector.

Every email is scored on 11 human-readable signals (lookalike sender, mismatched links, urgency, …).
A logistic regression learns how much each signal matters, so every verdict comes with reasons
an analyst — or an employee — can understand.

    python phishing.py          # build dataset, train, evaluate, export model for the live demo
"""
from __future__ import annotations

import json
import random
import re
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from sklearn.linear_model import LogisticRegression

HERE = Path(__file__).parent
SITE_DATA = HERE.parents[1] / "docs" / "demos" / "data"

# Fictional organizations used in the synthetic data
BRANDS = {"northbank": "northbank.com", "acmecloud": "acmecloud.com", "parcelgo": "parcelgo.com", "payflow": "payflow.com"}
COMPANY = "zephyrtech.com"   # the client's own domain
SUSPICIOUS_TLDS = (".top", ".xyz", ".click", ".zip", ".info", ".ru", ".cn", ".live")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd")
RISKY_EXT = (".html", ".htm", ".zip", ".iso", ".exe", ".js", ".lnk", ".xlsm", ".docm")
URGENCY = r"urgent|immediately|within 24 hours|final notice|suspended|locked|action required|expires? today|last chance|asap"
CREDS = r"verify your (account|identity)|confirm your (password|account|details)|log ?in to (restore|avoid|keep)|update your (payment|billing)|re-?enter|sign in to (unlock|restore)"
MONEY = r"gift card|wire transfer|bank details|invoice attached|payment overdue|bitcoin|crypto"
GENERIC = r"^(dear (customer|user|client|member|valued customer)|hello user)"

FEATURES = ["lookalike_sender", "display_name_mismatch", "reply_to_mismatch", "urgency", "credential_request",
            "link_text_mismatch", "suspicious_link_domain", "shortened_or_ip_link", "risky_attachment",
            "money_request", "generic_greeting"]
EXPLAIN = {
    "lookalike_sender": "Sender domain imitates a known brand",
    "display_name_mismatch": "Display name claims a brand the address doesn't match",
    "reply_to_mismatch": "Replies go to a different address than the sender",
    "urgency": "Pressure / urgency language",
    "credential_request": "Asks you to log in, verify or re-enter details",
    "link_text_mismatch": "Link text shows one site but points to another",
    "suspicious_link_domain": "Link goes to an unusual or lookalike domain",
    "shortened_or_ip_link": "Link hidden behind a shortener or raw IP address",
    "risky_attachment": "Attachment type often used for malware or fake logins",
    "money_request": "Asks for payment, gift cards or bank details",
    "generic_greeting": "Generic greeting instead of your name",
}


def domain(addr: str) -> str:
    return addr.split("@")[-1].lower() if "@" in addr else (urlparse(addr).hostname or addr).lower()


def lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_lookalike(d: str) -> bool:
    if d in BRANDS.values() or d == COMPANY or d.endswith("." + COMPANY):
        return False
    base = d.split(".")[0].replace("-", "")
    for b in list(BRANDS) + [COMPANY.split(".")[0]]:
        if b in base or lev(base, b) <= 2 or lev(base.replace("0", "o").replace("1", "l"), b) == 0:
            return True
    return False


def features(e: dict) -> dict[str, float]:
    text = (e["subject"] + " " + e["body"]).lower()
    sender = domain(e["from_addr"])
    links = e.get("links", [])
    hrefs = [domain(l["href"]) for l in links]
    name = e["from_name"].lower()
    claimed = [b for b in BRANDS if b in name.replace(" ", "")]
    return {
        "lookalike_sender": float(is_lookalike(sender)),
        "display_name_mismatch": float(bool(claimed) and sender != BRANDS[claimed[0]]),
        "reply_to_mismatch": float(bool(e.get("reply_to")) and domain(e["reply_to"]) != sender),
        "urgency": float(min(len(re.findall(URGENCY, text)), 3)),
        "credential_request": float(bool(re.search(CREDS, text))),
        "link_text_mismatch": float(any("." in l["text"] and domain("http://" + l["text"].split("/")[0].replace("https://", "").replace("http://", "")) != domain(l["href"]) for l in links)),
        "suspicious_link_domain": float(any(h.endswith(SUSPICIOUS_TLDS) or is_lookalike(h) for h in hrefs)),
        "shortened_or_ip_link": float(any(h in SHORTENERS or re.fullmatch(r"[\d.]+", h or "") for h in hrefs)),
        "risky_attachment": float(any(a.lower().endswith(RISKY_EXT) for a in e.get("attachments", []))),
        "money_request": float(bool(re.search(MONEY, text))),
        "generic_greeting": float(bool(re.search(GENERIC, e["body"].strip().lower()))),
    }


# ---------------- Synthetic dataset ----------------
def build_dataset(seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    names = ["Priya", "Marcus", "Elena", "Sam", "Wei", "Fatima", "Diego", "Hannah"]
    rows = []

    def phish():
        brand = rng.choice(list(BRANDS))
        look = rng.choice([f"{brand}-secure", f"{brand}-support", brand.replace("o", "0", 1), f"{brand}-verify", brand[:-1]])
        tld = rng.choice([".com", ".top", ".xyz", ".info", ".live"])
        sender = f"no-reply@{look}{tld}"
        kind = rng.choice(["creds", "creds", "invoice", "delivery", "giftcard", "subtle", "bec_vendor"])
        greet = rng.choice(["Dear customer,", "Dear valued customer,", "Hello user,", f"Hi {rng.choice(names)},"])
        link_host = rng.choice([f"{look}{tld}", "bit.ly", f"login-{brand}.click", "185.23.44.10"])
        if kind == "creds":
            subj = rng.choice(["Action required: your account is suspended", "Unusual sign-in detected", "Final notice: verify your account"])
            body = f"{greet} We detected unusual activity. Please verify your account within 24 hours or it will be locked. Click below to sign in to restore access."
            links = [{"text": f"www.{BRANDS[brand]}/secure", "href": f"https://{link_host}/auth"}]
            att = []
        elif kind == "invoice":
            subj = rng.choice(["Payment overdue - invoice attached", "Outstanding invoice #4471"])
            body = f"{greet} Your payment overdue notice is attached. Open the invoice attached immediately to avoid service interruption and update your payment details."
            links, att = [], [rng.choice(["Invoice_4471.html", "statement.zip", "invoice.iso", "INV-2026.xlsm"])]
        elif kind == "delivery":
            subj = "Your parcel could not be delivered"
            body = f"{greet} We attempted delivery. A small fee is required. Confirm your details within 24 hours or the package will be returned."
            links = [{"text": "Track parcel", "href": f"https://{link_host}/track"}]
            att = []
            brand, sender = "parcelgo", f"tracking@{rng.choice(['parcelg0', 'parcelgo-delivery', 'parce1go'])}{tld}"
        elif kind == "giftcard":
            sender = f"{rng.choice(['ceo.office', 'exec.assistant'])}@{rng.choice(['zephyrtech-mail.com', 'zephyr-tech.co', 'gmail.com'])}"
            subj = "Quick favor - urgent"
            body = f"Hi {rng.choice(names)}, are you at your desk? I need you to buy gift cards for a client today, it's urgent. Send me the codes asap. Don't call, I'm in a meeting."
            links, att = [], []
            return {"from_name": "Zephyr CEO", "from_addr": sender, "reply_to": "", "subject": subj, "body": body, "links": links, "attachments": att, "label": 1}
        elif kind == "bec_vendor":  # sent from a real, compromised vendor mailbox: very few signals
            v = rng.choice(list(BRANDS))
            return {"from_name": f"{v.title()} Accounts", "from_addr": f"accounts@{BRANDS[v]}", "reply_to": "",
                    "subject": "Updated remittance information", "body": f"Hi {rng.choice(names)}, " + rng.choice(["please note our bank details have changed. Use the new account for this month's payment.", "our banking information has changed. Please send this month's payment to the new account in the attached letter."]),
                    "links": [], "attachments": ["new_bank_details.pdf"], "label": 1}
        else:  # subtle: fewer signals
            subj = rng.choice(["Shared document: Q3 budget", "New voicemail received"])
            body = f"Hi {rng.choice(names)}, a file has been shared with you. Sign in to view it."
            links = [{"text": "Open document", "href": f"https://{rng.choice(['docs-' + brand + '.live', 'share-files.top', brand + '-drive.xyz'])}/view"}]
            att = []
        reply = rng.choice(["", "", f"help@{rng.choice(['mailbox.ru', 'support-desk.info', 'outlook-help.xyz'])}"])
        return {"from_name": f"{brand.title()} Security", "from_addr": sender, "reply_to": reply, "subject": subj, "body": body,
                "links": links, "attachments": att, "label": 1}

    def legit():
        kind = rng.choice(["internal", "internal", "brand", "brand", "newsletter", "reset", "invoice", "it_alert", "promo"])
        n = rng.choice(names)
        if kind == "internal":
            sender = f"{rng.choice(names).lower()}@{COMPANY}"
            subj = rng.choice(["Team lunch Friday", "Notes from today's standup", "Draft roadmap for review", "Reminder: timesheets due"])
            body = f"Hi {n}, " + rng.choice(["sharing the notes from today.", "can you review the draft by Thursday?", "lunch is at noon in the big room.", "please submit timesheets by Friday."])
            links = rng.choice([[], [{"text": "Roadmap doc", "href": f"https://docs.{COMPANY}/roadmap"}]])
            return {"from_name": sender.split("@")[0].title(), "from_addr": sender, "reply_to": "", "subject": subj, "body": body, "links": links,
                    "attachments": rng.choice([[], ["notes.pdf"], ["roadmap.docx"]]), "label": 0}
        if kind == "it_alert":  # genuine but phishy-sounding internal security notice
            return {"from_name": "Zephyr IT Security", "from_addr": f"security@{COMPANY}", "reply_to": "",
                    "subject": "Action required: security training due", "body": f"Hi {n}, action required: complete your annual security training within 24 hours or your account will be locked until it's done.",
                    "links": [{"text": "Start training", "href": f"https://training.{COMPANY}/start"}], "attachments": [], "label": 0}
        brand = rng.choice(list(BRANDS))
        d = BRANDS[brand]
        if kind == "promo":  # real marketing that uses a link shortener and urgency
            return {"from_name": brand.title(), "from_addr": f"offers@{d}", "reply_to": "", "subject": "Last chance: 20% off expires today",
                    "body": "Dear customer, last chance! Our sale expires today.", "links": [{"text": "Shop now", "href": "https://bit.ly/3xYz"}], "attachments": [], "label": 0}
        if kind == "brand":
            subj = rng.choice(["Your monthly statement is ready", "Your order has shipped", "Receipt for your payment"])
            body = f"Hi {n}, " + rng.choice(["your statement is available in the app.", "your order is on its way.", "thanks for your payment. No action is needed."])
            links = [{"text": f"www.{d}/account", "href": f"https://www.{d}/account"}]
        elif kind == "newsletter":
            subj = rng.choice(["What's new this month", "Last chance: early-bird webinar seats"])
            body = f"Hi {n}, here are this month's product updates and tips."
            links = [{"text": "Read more", "href": f"https://news.{d}/october"}]
        elif kind == "reset":
            subj = "Password reset requested"
            body = f"Hi {n}, you asked to reset your password. If this was you, use the link below. It expires today. If it wasn't you, ignore this email."
            links = [{"text": "Reset password", "href": f"https://accounts.{d}/reset"}]
        else:
            subj = rng.choice(["Invoice for October", "Reminder: payment overdue"])
            body = f"Hi {n}, " + rng.choice(["your October invoice is attached. It will be charged automatically on the 15th.", "friendly reminder that invoice 1182 is now payment overdue. Invoice attached for your records."])
            links = []
        return {"from_name": brand.title(), "from_addr": f"notifications@{d}", "reply_to": "", "subject": subj, "body": body,
                "links": links, "attachments": ["invoice.pdf"] if kind == "invoice" else [], "label": 0}

    for i in range(300):
        rows.append(phish() if i % 2 == 0 else legit())
    return rows


def split(rows):
    return [r for i, r in enumerate(rows) if i % 5 != 4], [r for i, r in enumerate(rows) if i % 5 == 4]


def matrix(rows):
    return np.array([[features(r)[f] for f in FEATURES] for r in rows]), np.array([r["label"] for r in rows])


def train(rows) -> LogisticRegression:
    X, y = matrix(rows)
    return LogisticRegression(C=1.0, max_iter=1000).fit(X, y)


def score(model, email: dict) -> tuple[float, list[tuple[str, float]]]:
    f = features(email)
    x = np.array([[f[k] for k in FEATURES]])
    p = float(model.predict_proba(x)[0, 1])
    reasons = sorted(((EXPLAIN[k], model.coef_[0][i] * f[k]) for i, k in enumerate(FEATURES) if f[k]), key=lambda r: -r[1])
    return p, reasons


def evaluate(model, rows, threshold: float = 0.5) -> dict:
    X, y = matrix(rows)
    pred = (model.predict_proba(X)[:, 1] >= threshold).astype(int)
    tp, fp = int(((pred == 1) & (y == 1)).sum()), int(((pred == 1) & (y == 0)).sum())
    fn, tn = int(((pred == 0) & (y == 1)).sum()), int(((pred == 0) & (y == 0)).sum())
    return {"accuracy": (tp + tn) / len(y), "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def export(model, rows) -> None:
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    _, test = split(rows)
    out = {"features": FEATURES, "explain": EXPLAIN, "weights": model.coef_[0].round(4).tolist(),
           "bias": round(float(model.intercept_[0]), 4), "test": test,
           "config": {"brands": BRANDS, "company": COMPANY, "suspicious_tlds": SUSPICIOUS_TLDS, "shorteners": SHORTENERS, "risky_ext": RISKY_EXT,
                      "urgency": URGENCY, "creds": CREDS, "money": MONEY, "generic": GENERIC}}
    (SITE_DATA / "phishing_model.json").write_text(json.dumps(out), encoding="utf-8")
    (HERE / "emails.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")


if __name__ == "__main__":
    rows = build_dataset()
    tr, te = split(rows)
    model = train(tr)
    m = evaluate(model, te)
    print(f"Train {len(tr)} / test {len(te)} emails")
    print(f"Accuracy {m['accuracy']:.0%} · precision {m['precision']:.0%} · recall {m['recall']:.0%}  (TP {m['tp']} FP {m['fp']} FN {m['fn']} TN {m['tn']})\n")
    print("Learned signal weights (higher = more phishy):")
    for f, w in sorted(zip(FEATURES, model.coef_[0]), key=lambda x: -x[1]):
        print(f"  {w:+.2f}  {EXPLAIN[f]}")
    export(model, rows)
    print("\nExported model → docs/demos/data/phishing_model.json")
