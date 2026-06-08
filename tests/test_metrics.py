import eval.metrics as M


def test_accuracy_and_near():
    pairs = [("CRITICAL", "CRITICAL"), ("CRITICAL", "HIGH"), ("HIGH", "HIGH"),
             ("MEDIUM", "LOW"), ("INFO", "bogus")]
    assert M.accuracy(pairs) == 2 / 5
    # exact(2) + CRIT/HIGH near + MED/LOW near = 4/5 ; INFO/bogus invalid -> miss
    assert M.near_accuracy(pairs) == 4 / 5


def test_per_class_prf_handles_invalid_pred():
    pairs = [("HIGH", "HIGH"), ("HIGH", "HIGH"), ("CRITICAL", "HIGH"), ("INFO", "bogus")]
    prf = M.per_class_prf(pairs)
    assert prf["HIGH"]["precision"] == 2 / 3  # one CRITICAL mislabeled HIGH
    assert prf["HIGH"]["recall"] == 1.0
    assert prf["INFO"]["recall"] == 0.0       # INFO -> invalid counts as FN


def test_confusion_matrix_invalid_bucket():
    cm = M.confusion_matrix([("INFO", "bogus"), ("CRITICAL", "HIGH")])
    assert cm["INFO"]["__invalid__"] == 1
    assert cm["CRITICAL"]["HIGH"] == 1


def test_cohen_kappa_bounds():
    assert M.cohen_kappa([("HIGH", "HIGH"), ("LOW", "LOW")]) == 1.0
    assert M.cohen_kappa([("HIGH", "LOW"), ("LOW", "HIGH")]) <= 0


def test_cve_and_product_metrics():
    assert M.cve_prf(["CVE-2024-1"], ["cve-2024-1"]) == (1.0, 1.0, 1.0)
    assert M.cve_prf([], []) == (1.0, 1.0, 1.0)
    p, r, f = M.cve_prf(["CVE-2024-1", "CVE-2024-2"], ["CVE-2024-1", "CVE-2024-9"])
    assert p == 0.5 and r == 0.5
    assert M.product_recall(["Apache Struts"], ["apache", "struts"]) == 1.0
    assert M.product_recall(["Apache Struts"], ["nginx"]) == 0.0
    assert M.product_recall([], ["x"]) == 1.0


def test_evaluate_perfect():
    recs = [{"true_level": "HIGH", "pred_level": "HIGH", "true_cves": ["CVE-2024-1"],
             "pred_cves": ["CVE-2024-1"], "true_products": ["Lodash"],
             "pred_products": ["lodash"], "latency_ms": 100}]
    out = M.evaluate(recs)
    assert out["level_accuracy"] == 1.0 and out["macro_f1"] == 1.0
    assert out["cve_f1"] == 1.0 and out["product_recall"] == 1.0
    assert out["latency_ms_mean"] == 100
