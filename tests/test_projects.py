import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "projects"
for name in ["01-llm-redteam-harness", "02-phishing-detector", "03-log-anomaly-detection",
             "04-adversarial-ml-lab", "05-attack-coverage-map", "06-vuln-prioritizer",
             "07-bilingual-injection-probes"]:
    sys.path.insert(0, str(ROOT / name))

import attack_coverage as coverage  # noqa: E402
import bilingual  # noqa: E402
import detect  # noqa: E402
import lab  # noqa: E402
import phishing  # noqa: E402
import prioritize  # noqa: E402
import redteam  # noqa: E402


def score(defenses):
    return sum(not r["failed"] for r in redteam.run(redteam.SimulatedBot(defenses)))


def test_redteam_defense_in_depth():
    assert score(redteam.Defenses()) == 1                                   # only the control passes
    assert score(redteam.Defenses(input_filter=True)) == 3                  # keyword filter is weak
    assert score(redteam.Defenses(True, True, True, True, True)) == 10      # layered defense holds
    assert all("hours" in redteam.SimulatedBot(redteam.Defenses(True, True, True, True, True)).respond(p).text
               for p in ["What are your support hours?"])                   # and doesn't break normal use


def test_phishing_detector():
    rows = phishing.build_dataset()
    train, test = phishing.split(rows)
    m = phishing.evaluate(phishing.train(train), test)
    assert m["accuracy"] >= 0.9 and m["precision"] >= 0.95
    assert phishing.is_lookalike("n0rthbank.top") and not phishing.is_lookalike("northbank.com")


def test_log_detection_catches_all_incidents():
    ev = detect.generate()
    for level in (1, 3, 5):
        r = detect.evaluate(ev, detect.detect(ev, level))
        assert r["caught"] == r["incidents"] == 5
    quiet, loud = detect.detect(ev, 1), detect.detect(ev, 5)
    assert len(quiet) < len(loud)
    assert all(a["ip"].startswith(("198.51.100.", "203.0.113.", "192.0.2.")) for a in loud)   # RFC 5737 only


def test_adversarial_ml_story():
    train, test = lab.split(lab.build_dataset())
    base = lab.NaiveBayes().fit(train)
    hard = lab.NaiveBayes(normalize=True).fit(lab.augment(train, __import__("random").Random(1)))
    assert lab.evasion_rate(base, test) > 0.4 and lab.evasion_rate(hard, test) < 0.1
    undefended = dict(lab.poisoning_curve(train, test))
    defended = dict(lab.poisoning_curve(train, test, sanitized=True))
    assert undefended[90] < 0.6 and defended[90] > 0.9


def test_attack_coverage():
    base, boosted = coverage.coverage(False), coverage.coverage(True)
    assert boosted["weighted"] > base["weighted"]
    assert coverage.gaps()[0]["id"] in {"T1078", "T1110"}
    assert "Purple-team test plan" in coverage.plan()


def test_vuln_prioritizer_beats_cvss():
    fs = prioritize.build_findings()
    cvss = prioritize.outcome(fs, prioritize.rank(fs, "cvss"), 10)
    risk = prioritize.outcome(fs, prioritize.rank(fs, "risk"), 10)
    assert risk["risk_removed"] > cvss["risk_removed"] + 0.3
    assert risk["kev_fixed"] == risk["kev_total"]


def test_bilingual_normalization_and_defense_in_depth():
    # normalization canonicalizes full-width and strips zero-width characters
    assert bilingual.normalize("Ｉｇｎｏｒｅ　ａｌｌ") == "Ignore all"
    assert bilingual.normalize("ig​nore") == "ignore"

    def defended(d):
        return sum(not r["failed"] for r in bilingual.run(bilingual.SimulatedBot(d)))

    # an English-only filter catches none of the multilingual probes (only the control passes)
    assert defended(bilingual.Defenses()) == 1
    # normalization alone handles the character tricks but not the Chinese-language ones
    assert defended(bilingual.Defenses(normalize_input=True)) == 3
    # full defense in depth catches everything without breaking the normal request
    assert defended(bilingual.Defenses(True, True, True, True)) == 10
