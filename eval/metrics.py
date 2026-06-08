"""
Pure evaluation metrics for threat-intel analysis quality.

No I/O, no network — every function takes data and returns numbers, so the math
is unit-testable without a live model. Used by eval/benchmark.py to score each
provider's predictions against the hand-labeled gold set.
"""

import math
import re

LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_TOKEN = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN.split(str(text).lower()) if t}


# ── Threat-level classification ────────────────────────────────────────────────

def confusion_matrix(pairs, labels=LEVEL_ORDER) -> dict:
    """pairs: list of (true, pred). Return cm[true][pred] over valid labels.

    Predictions outside `labels` are tallied in cm[true]["__invalid__"] so the
    row still sums to the true-class support.
    """
    cm = {t: {p: 0 for p in labels} for t in labels}
    for t in labels:
        cm[t]["__invalid__"] = 0
    for true, pred in pairs:
        if true not in cm:
            continue
        if pred in labels:
            cm[true][pred] += 1
        else:
            cm[true]["__invalid__"] += 1
    return cm


def per_class_prf(pairs, labels=LEVEL_ORDER) -> dict:
    """Per-class precision/recall/F1/support computed straight from pairs.

    Invalid predictions (not in labels) count as a miss for the true class
    (FN) and never inflate any class's precision.
    """
    out = {}
    for c in labels:
        tp = sum(1 for t, p in pairs if t == c and p == c)
        fp = sum(1 for t, p in pairs if t != c and p == c)
        fn = sum(1 for t, p in pairs if t == c and p != c)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        out[c] = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}
    return out


def macro_f1(prf: dict) -> float:
    """Unweighted mean F1 over classes that have support."""
    fs = [v["f1"] for v in prf.values() if v["support"] > 0]
    return sum(fs) / len(fs) if fs else 0.0


def accuracy(pairs) -> float:
    if not pairs:
        return 0.0
    return sum(1 for t, p in pairs if t == p) / len(pairs)


def near_accuracy(pairs, order=LEVEL_ORDER) -> float:
    """Fraction within +/-1 step of severity order (invalid pred counts as miss)."""
    if not pairs:
        return 0.0
    ok = 0
    for t, p in pairs:
        if t in order and p in order and abs(order.index(t) - order.index(p)) <= 1:
            ok += 1
    return ok / len(pairs)


def cohen_kappa(pairs, labels=LEVEL_ORDER) -> float:
    """Cohen's kappa between true and predicted labels (chance-corrected)."""
    valid = [(t, p) for t, p in pairs if t in labels and p in labels]
    n = len(valid)
    if n == 0:
        return 0.0
    po = sum(1 for t, p in valid if t == p) / n
    true_counts = {l: 0 for l in labels}
    pred_counts = {l: 0 for l in labels}
    for t, p in valid:
        true_counts[t] += 1
        pred_counts[p] += 1
    pe = sum((true_counts[l] / n) * (pred_counts[l] / n) for l in labels)
    if math.isclose(pe, 1.0):
        return 1.0 if math.isclose(po, 1.0) else 0.0
    return (po - pe) / (1 - pe)


# ── Set / entity metrics ───────────────────────────────────────────────────────

def set_prf(true_set: set, pred_set: set) -> tuple[float, float, float]:
    """Precision/recall/F1 for two sets. Both empty -> perfect (nothing to find)."""
    if not true_set and not pred_set:
        return 1.0, 1.0, 1.0
    tp = len(true_set & pred_set)
    precision = tp / len(pred_set) if pred_set else 0.0
    recall = tp / len(true_set) if true_set else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def cve_prf(true_cves, pred_cves) -> tuple[float, float, float]:
    return set_prf({c.upper() for c in true_cves}, {c.upper() for c in pred_cves})


def product_recall(true_products, pred_products) -> float:
    """Token-level recall: fraction of gold-product tokens present in prediction."""
    true_t = set().union(*(_tokens(p) for p in true_products)) if true_products else set()
    pred_t = set().union(*(_tokens(p) for p in pred_products)) if pred_products else set()
    if not true_t:
        return 1.0
    return len(true_t & pred_t) / len(true_t)


# ── Aggregation ────────────────────────────────────────────────────────────────

def evaluate(records: list[dict], labels=LEVEL_ORDER) -> dict:
    """Aggregate metrics over prediction records.

    Each record: {true_level, pred_level, true_cves, pred_cves,
                  true_products, pred_products, latency_ms?}.
    """
    pairs = [(r["true_level"], r["pred_level"]) for r in records]
    prf = per_class_prf(pairs, labels)

    cve_p = cve_r = cve_f = 0.0
    prod_r = 0.0
    for r in records:
        p, rec, f = cve_prf(r.get("true_cves", []), r.get("pred_cves", []))
        cve_p += p
        cve_r += rec
        cve_f += f
        prod_r += product_recall(r.get("true_products", []), r.get("pred_products", []))
    n = len(records) or 1

    latencies = [r["latency_ms"] for r in records if r.get("latency_ms") is not None]

    return {
        "n": len(records),
        "level_accuracy": accuracy(pairs),
        "level_near_accuracy": near_accuracy(pairs, labels),
        "macro_f1": macro_f1(prf),
        "cohen_kappa": cohen_kappa(pairs, labels),
        "per_class": prf,
        "confusion_matrix": confusion_matrix(pairs, labels),
        "cve_precision": cve_p / n,
        "cve_recall": cve_r / n,
        "cve_f1": cve_f / n,
        "product_recall": prod_r / n,
        "latency_ms_mean": (sum(latencies) / len(latencies)) if latencies else None,
        "labels": list(labels),
    }
