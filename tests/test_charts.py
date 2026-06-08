import reporting.charts_svg as C


def _valid(svg):
    return svg.startswith("<svg") and svg.endswith("</svg>") and "None" not in svg and "NaN" not in svg


def test_bar_chart():
    assert _valid(C.bar_chart({"CRITICAL": 30, "HIGH": 102}, color_map=C.LEVEL_COLORS))


def test_hbar_chart():
    assert _valid(C.hbar_chart({"NVD": 114, "iThome": 45}))


def test_grouped_bar():
    assert _valid(C.grouped_bar(["CRITICAL", "HIGH"], {"a": [0.6, 0.7], "b": [0.8, 0.9]}))


def test_heatmap():
    assert _valid(C.heatmap([[10, 2], [1, 40]], ["CRITICAL", "HIGH"], ["CRITICAL", "HIGH"]))


def test_empty_inputs_safe():
    assert C.bar_chart({}).startswith("<svg")
    assert C.heatmap([], [], []).startswith("<svg")
