/* ============================================================
   CloudHawk Console — charts (vanilla SVG, string builders)
   Exposes window.CHART
   ============================================================ */
(function () {
  "use strict";

  /* Donut: data = [{label, value, color}], center = {value, label} */
  function donut(data, opts) {
    opts = opts || {};
    const size = opts.size || 150, thickness = opts.thickness || 18;
    const total = data.reduce((s, d) => s + d.value, 0) || 1;
    const r = (size - thickness) / 2, cx = size / 2, cy = size / 2;
    const circ = 2 * Math.PI * r;
    let offset = 0;
    let segs = "";
    data.forEach(d => {
      const len = (d.value / total) * circ;
      segs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + d.color +
        '" stroke-width="' + thickness + '" stroke-dasharray="' + len.toFixed(2) + ' ' + (circ - len).toFixed(2) +
        '" stroke-dashoffset="' + (-offset).toFixed(2) + '" stroke-linecap="butt" style="transition:stroke-dasharray .6s ease,stroke-dashoffset .6s ease"/>';
      offset += len;
    });
    let center = "";
    if (opts.center) {
      center = '<g style="transform:rotate(90deg);transform-origin:center">' +
        '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" font-size="26" font-weight="700" fill="var(--text)" font-family="var(--mono)">' + opts.center.value + '</text>' +
        '<text x="' + cx + '" y="' + (cy + 15) + '" text-anchor="middle" font-size="10" fill="var(--text-dim)" letter-spacing="1.5" font-family="var(--mono)">' + opts.center.label + '</text></g>';
    }
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" style="transform:rotate(-90deg)">' +
      '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="var(--line)" stroke-width="' + thickness + '" opacity="0.5"/>' +
      segs + center + '</svg>';
  }

  /* Horizontal bars: data = [{label, value, color}] */
  function hbars(data, opts) {
    opts = opts || {};
    const m = opts.max || Math.max.apply(null, data.map(d => d.value).concat([1]));
    let rows = "";
    data.forEach(d => {
      rows += '<div class="hbar-row"><div class="hbar-label" title="' + CH.esc(d.label) + '">' + CH.esc(d.label) + '</div>' +
        '<div class="hbar-track"><div class="hbar-fill" style="width:' + (d.value / m * 100) + '%;background:' + d.color + '"></div></div>' +
        '<div class="hbar-val mono">' + d.value + '</div></div>';
    });
    return '<div class="hbars">' + rows + '</div>';
  }

  /* Area trend. values = number[] */
  function area(values, opts) {
    opts = opts || {};
    const width = opts.width || 560, height = opts.height || 90;
    const color = opts.color || "var(--accent)", fillOpacity = opts.fillOpacity == null ? 0.16 : opts.fillOpacity;
    const max = Math.max.apply(null, values.concat([1]));
    const n = values.length || 1;
    const stepX = width / Math.max(1, n - 1);
    const pts = values.map((v, i) => [i * stepX, height - (v / max) * (height - 8) - 4]);
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const areaPath = line + " L " + width + " " + height + " L 0 " + height + " Z";
    const gid = "ag" + Math.round(width) + "_" + Math.round((values[0] || 0) * 10) + "_" + n;
    const last = pts[pts.length - 1];
    return '<svg width="100%" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none" style="display:block">' +
      '<defs><linearGradient id="' + gid + '" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="' + color + '" stop-opacity="' + fillOpacity + '"/>' +
      '<stop offset="100%" stop-color="' + color + '" stop-opacity="0"/></linearGradient></defs>' +
      '<path d="' + areaPath + '" fill="url(#' + gid + ')"/>' +
      '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>' +
      (last ? '<circle cx="' + last[0].toFixed(1) + '" cy="' + last[1].toFixed(1) + '" r="3" fill="' + color + '"/>' : "") +
      '</svg>';
  }

  /* Stacked severity columns. buckets = [{label, sev:{CRITICAL,...}}] */
  function stackedCols(buckets, opts) {
    opts = opts || {};
    const height = opts.height || 150;
    const order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const colors = { CRITICAL: "var(--sev-crit)", HIGH: "var(--sev-high)", MEDIUM: "var(--sev-med)", LOW: "var(--sev-low)" };
    const max = Math.max.apply(null, buckets.map(b => order.reduce((s, k) => s + (b.sev[k] || 0), 0)).concat([1]));
    let cols = "";
    buckets.forEach(b => {
      const tot = order.reduce((s, k) => s + (b.sev[k] || 0), 0);
      let segs = "";
      order.forEach(k => {
        const v = b.sev[k] || 0;
        if (v) segs += '<div class="scol-seg" style="height:' + (v / max * 100) + '%;background:' + colors[k] + '"></div>';
      });
      cols += '<div class="scol" title="' + CH.esc(b.label) + ': ' + tot + '"><div class="scol-stack">' + segs + '</div></div>';
    });
    return '<div class="stacked-cols" style="height:' + height + 'px">' + cols + '</div>';
  }

  window.CHART = { donut, hbars, area, stackedCols };
})();
