"""
Zero-dependency inline-SVG charts.

Every function returns an SVG string that embeds directly into an HTML report —
no matplotlib, no JS, no network. Reports therefore open in any browser and
survive being emailed or saved as a single file. Colors are fixed (reports are
rendered on a white page), text is dark, numbers are rounded.
"""

import html as _html

# A small categorical palette (Anthropic-ish ramp mid-tones).
PALETTE = ["#378ADD", "#1D9E75", "#534AB7", "#D85A30", "#EF9F27", "#888780"]
LEVEL_COLORS = {
    "CRITICAL": "#E24B4A", "HIGH": "#D85A30", "MEDIUM": "#EF9F27",
    "LOW": "#639922", "INFO": "#888780",
}


def _esc(s) -> str:
    return _html.escape(str(s))


def _fmt(v) -> str:
    f = float(v)
    return str(int(round(f))) if abs(f - round(f)) < 1e-9 else f"{f:.2f}"


def bar_chart(data: dict, width=560, height=240, color=None, color_map=None, title=None) -> str:
    """Vertical bar chart. data: {label: value}. color_map overrides per-label."""
    items = list(data.items())
    if not items:
        return '<svg width="10" height="10"></svg>'
    pad_l, pad_b, pad_t, pad_r = 40, 46, 24 if title else 12, 12
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_b - pad_t
    vmax = max([float(v) for _, v in items] + [1])
    n = len(items)
    gap = 12
    bw = (plot_w - gap * (n - 1)) / n
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
             f'font-family="system-ui,sans-serif" role="img">']
    if title:
        parts.append(f'<text x="{pad_l}" y="16" font-size="13" font-weight="600" fill="#1a1a1a">{_esc(title)}</text>')
    # baseline
    base_y = pad_t + plot_h
    parts.append(f'<line x1="{pad_l}" y1="{base_y}" x2="{width-pad_r}" y2="{base_y}" stroke="#ddd"/>')
    for i, (label, val) in enumerate(items):
        v = float(val)
        bh = (v / vmax) * plot_h
        x = pad_l + i * (bw + gap)
        y = base_y - bh
        c = (color_map or {}).get(label) or color or PALETTE[i % len(PALETTE)]
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bh:.1f}" fill="{c}" rx="2"/>')
        parts.append(f'<text x="{x+bw/2:.1f}" y="{y-4:.1f}" font-size="11" text-anchor="middle" fill="#555">{_fmt(v)}</text>')
        parts.append(f'<text x="{x+bw/2:.1f}" y="{base_y+16:.1f}" font-size="11" text-anchor="middle" fill="#555">{_esc(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def hbar_chart(data: dict, width=560, row_h=26, color=None, color_map=None, title=None) -> str:
    """Horizontal bar chart — good for long labels (products, CVEs)."""
    items = list(data.items())
    if not items:
        return '<svg width="10" height="10"></svg>'
    pad_l, pad_r, pad_t = 160, 44, 24 if title else 8
    height = pad_t + row_h * len(items) + 8
    plot_w = width - pad_l - pad_r
    vmax = max([float(v) for _, v in items] + [1])
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
             f'font-family="system-ui,sans-serif" role="img">']
    if title:
        parts.append(f'<text x="8" y="16" font-size="13" font-weight="600" fill="#1a1a1a">{_esc(title)}</text>')
    for i, (label, val) in enumerate(items):
        v = float(val)
        bw = (v / vmax) * plot_w
        y = pad_t + i * row_h
        c = (color_map or {}).get(label) or color or PALETTE[i % len(PALETTE)]
        lbl = _esc(label if len(str(label)) <= 24 else str(label)[:23] + "…")
        parts.append(f'<text x="{pad_l-8}" y="{y+row_h/2+4:.1f}" font-size="11" text-anchor="end" fill="#555">{lbl}</text>')
        parts.append(f'<rect x="{pad_l}" y="{y+3:.1f}" width="{max(bw,1):.1f}" height="{row_h-8}" fill="{c}" rx="2"/>')
        parts.append(f'<text x="{pad_l+bw+5:.1f}" y="{y+row_h/2+4:.1f}" font-size="11" fill="#555">{_fmt(v)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def grouped_bar(categories, series: dict, width=560, height=260, colors=None, title=None) -> str:
    """Grouped vertical bars. series: {series_name: [values aligned to categories]}."""
    if not categories or not series:
        return '<svg width="10" height="10"></svg>'
    colors = colors or PALETTE
    pad_l, pad_b, pad_t, pad_r = 40, 64, 28 if title else 12, 12
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_b - pad_t
    vmax = max([float(v) for vals in series.values() for v in vals] + [1])
    ncat = len(categories)
    nser = len(series)
    group_gap = 18
    gw = (plot_w - group_gap * (ncat - 1)) / ncat
    bw = gw / nser
    base_y = pad_t + plot_h
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
             f'font-family="system-ui,sans-serif" role="img">']
    if title:
        parts.append(f'<text x="{pad_l}" y="16" font-size="13" font-weight="600" fill="#1a1a1a">{_esc(title)}</text>')
    parts.append(f'<line x1="{pad_l}" y1="{base_y}" x2="{width-pad_r}" y2="{base_y}" stroke="#ddd"/>')
    for ci, cat in enumerate(categories):
        gx = pad_l + ci * (gw + group_gap)
        for si, (sname, vals) in enumerate(series.items()):
            v = float(vals[ci])
            bh = (v / vmax) * plot_h
            x = gx + si * bw
            parts.append(f'<rect x="{x:.1f}" y="{base_y-bh:.1f}" width="{bw-2:.1f}" height="{bh:.1f}" '
                         f'fill="{colors[si % len(colors)]}" rx="1"/>')
        parts.append(f'<text x="{gx+gw/2:.1f}" y="{base_y+16:.1f}" font-size="11" text-anchor="middle" fill="#555">{_esc(cat)}</text>')
    # legend
    lx = pad_l
    ly = height - 20
    for si, sname in enumerate(series):
        parts.append(f'<rect x="{lx}" y="{ly-9}" width="10" height="10" fill="{colors[si % len(colors)]}" rx="2"/>')
        parts.append(f'<text x="{lx+15}" y="{ly}" font-size="11" fill="#555">{_esc(sname)}</text>')
        lx += 22 + 7 * len(str(sname))
    parts.append("</svg>")
    return "".join(parts)


def heatmap(matrix, row_labels, col_labels, width=420, title=None, base_color=(55, 138, 221)) -> str:
    """Confusion-matrix style heatmap. matrix[i][j] aligned to row/col labels."""
    if not matrix:
        return '<svg width="10" height="10"></svg>'
    pad_l, pad_t, pad_r, pad_b = 80, (52 if title else 36), 12, 24
    n_rows, n_cols = len(row_labels), len(col_labels)
    cell = (width - pad_l - pad_r) / max(n_cols, 1)
    height = pad_t + cell * n_rows + pad_b
    vmax = max([max(r) for r in matrix] + [1])
    br, bg, bb = base_color
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" '
             f'font-family="system-ui,sans-serif" role="img">']
    if title:
        parts.append(f'<text x="8" y="16" font-size="13" font-weight="600" fill="#1a1a1a">{_esc(title)}</text>')
        parts.append(f'<text x="8" y="32" font-size="10" fill="#888">列=正解 (true) · 欄=預測 (pred)</text>')
    for j, cl in enumerate(col_labels):
        cx = pad_l + j * cell + cell / 2
        parts.append(f'<text x="{cx:.1f}" y="{pad_t-6}" font-size="10" text-anchor="middle" fill="#555">{_esc(cl)}</text>')
    for i, rl in enumerate(row_labels):
        ry = pad_t + i * cell
        parts.append(f'<text x="{pad_l-6}" y="{ry+cell/2+4:.1f}" font-size="10" text-anchor="end" fill="#555">{_esc(rl)}</text>')
        for j in range(n_cols):
            v = float(matrix[i][j])
            inten = v / vmax
            # white -> base_color
            r = int(255 - (255 - br) * inten)
            g = int(255 - (255 - bg) * inten)
            b = int(255 - (255 - bb) * inten)
            x = pad_l + j * cell
            txt_fill = "#fff" if inten > 0.55 else "#333"
            parts.append(f'<rect x="{x:.1f}" y="{ry:.1f}" width="{cell:.1f}" height="{cell:.1f}" '
                         f'fill="rgb({r},{g},{b})" stroke="#eee"/>')
            if v:
                parts.append(f'<text x="{x+cell/2:.1f}" y="{ry+cell/2+4:.1f}" font-size="11" '
                             f'text-anchor="middle" fill="{txt_fill}">{_fmt(v)}</text>')
    parts.append("</svg>")
    return "".join(parts)
