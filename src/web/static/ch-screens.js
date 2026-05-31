/* ============================================================
   CloudHawk Console — screens (plain JS string rendering)
   overview · alerts · timeline · rules · compliance (+ drawer)
   Exposes window.SCREENS and a shared APP state object.
   ============================================================ */
(function () {
  "use strict";
  const { icon, esc, sevTag, sevDot, cloudBadge, statusPill, sevRank, ago, fmtTime } = CH;

  /* ---------------- download helpers ---------------- */
  function downloadAs(content, filename, mime) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type: mime }));
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  function alertsToCSV(rows) {
    const cols = ["timestamp", "severity", "title", "rule_id", "service", "cloud", "resource_id", "status", "description", "remediation"];
    const q = v => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
    return [cols.join(","), ...rows.map(a => cols.map(c => q(a[c])).join(","))].join("\r\n");
  }
  function rulesToYAML(rules) {
    const lines = ["rules:"];
    rules.forEach(r => {
      lines.push("  - id: " + (r.id || ""));
      ["title", "description", "service", "severity", "owasp", "condition", "remediation"].forEach(k => {
        lines.push("    " + k + ": " + JSON.stringify(r[k] || ""));
      });
    });
    return lines.join("\n");
  }
  function complianceToCSV(cats) {
    const cols = ["owasp", "rules", "findings", "critical"];
    const q = v => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
    return [cols.join(","), ...cats.map(c => cols.map(col => q(c[col])).join(","))].join("\r\n");
  }
  function stamp() { return new Date().toISOString().slice(0, 10); }

  /* ---------------- shared state ---------------- */
  const APP = {
    alerts: [], rules: [], ruleMap: {},
    live: true,
    drawerId: null,
    onChange: null, // optional hook for nav badge refresh
  };
  window.APP = APP;

  function isPreview() { return !!window.__CH_PREVIEW; }

  function apiPost(url, body) {
    if (isPreview()) return Promise.resolve(null);
    return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(r => r.json()).catch(() => null);
  }

  /* ---------------- toast ---------------- */
  function toast(msg, kind) {
    let wrap = document.querySelector(".toast-wrap");
    if (!wrap) { wrap = document.createElement("div"); wrap.className = "toast-wrap"; document.body.appendChild(wrap); }
    const el = document.createElement("div");
    el.className = "toast " + (kind || "info");
    el.innerHTML = icon(kind === "err" ? "alert" : kind === "ok" ? "check" : "bell", { size: 16 }) + "<span>" + esc(msg) + "</span>";
    wrap.appendChild(el);
    setTimeout(() => { el.style.opacity = "0"; el.style.transition = ".3s"; setTimeout(() => el.remove(), 300); }, 3200);
  }
  APP.toast = toast;

  /* ---------------- mutations ---------------- */
  function setStatus(ids, status) {
    const s = new Set(ids);
    // capture identity fields BEFORE mutating, for backend persistence
    const payload = APP.alerts.filter(a => s.has(a.id)).map(a => ({ rule_id: a.rule_id, resource_id: a.resource_id, timestamp: a.timestamp }));
    APP.alerts = APP.alerts.map(a => s.has(a.id) ? Object.assign({}, a, { status }) : a);
    apiPost("/api/alerts/status", { status, alerts: payload }); // no-op in preview
    if (APP.onChange) APP.onChange();
  }
  APP.onAck = ids => { setStatus(ids, "ACKNOWLEDGED"); toast(ids.length + " alert(s) acknowledged", "ok"); };
  APP.onResolve = ids => { setStatus(ids, "RESOLVED"); toast(ids.length + " alert(s) resolved", "ok"); };
  APP.onSuppress = ids => {
    const ruleIds = new Set(APP.alerts.filter(a => ids.includes(a.id)).map(a => a.rule_id));
    APP.rules = APP.rules.map(r => ruleIds.has(r.id) ? Object.assign({}, r, { enabled: false }) : r);
    setStatus(ids, "RESOLVED");
    apiPost("/api/rules/bulk-edit", { ids: [...ruleIds], status: "disabled" });
    toast("Suppressed " + ruleIds.size + " rule(s)", "ok");
  };
  APP.onToggleRule = id => {
    let nowOn = false;
    APP.rules = APP.rules.map(r => { if (r.id === id) { nowOn = !r.enabled; return Object.assign({}, r, { enabled: nowOn }); } return r; });
    apiPost("/api/rules/bulk-edit", { ids: [id], status: nowOn ? "enabled" : "disabled" });
  };
  APP.onBulkRules = (ids, action) => {
    if (action === "enable" || action === "disable") {
      const on = action === "enable";
      const s = new Set(ids);
      APP.rules = APP.rules.map(r => s.has(r.id) ? Object.assign({}, r, { enabled: on }) : r);
      apiPost("/api/rules/bulk-edit", { ids, status: on ? "enabled" : "disabled" });
      toast(ids.length + " rule(s) " + (on ? "enabled" : "disabled"), "ok");
    } else if (action === "export") {
      const sel = APP.rules.filter(r => ids.includes(r.id));
      downloadAs(rulesToYAML(sel), "cloudhawk-rules-" + stamp() + ".yaml", "text/yaml");
      toast("Exported " + ids.length + " rule(s) as YAML", "ok");
    }
  };

  /* ---------------- cloud console deep-link (#3) ---------------- */
  function consoleUrl(a) {
    const region = a.region || "us-east-1";
    const res = a.resource_id || "";
    if (a.cloud === "aws") {
      switch (a.service) {
        case "EC2": return "https://console.aws.amazon.com/ec2/home?region=" + region + "#SecurityGroup:groupId=" + res;
        case "S3": return "https://s3.console.aws.amazon.com/s3/buckets/" + encodeURIComponent(res);
        case "IAM": return "https://console.aws.amazon.com/iam/home#/users";
        case "RDS": return "https://console.aws.amazon.com/rds/home?region=" + region + "#databases:";
        case "CloudTrail": return "https://console.aws.amazon.com/cloudtrail/home?region=" + region;
        case "GuardDuty": return "https://console.aws.amazon.com/guardduty/home?region=" + region;
        default: return "https://console.aws.amazon.com/console/home?region=" + region;
      }
    }
    if (a.cloud === "gcp") return "https://console.cloud.google.com/security/command-center/findings";
    if (a.cloud === "azure") return "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0";
    return "#";
  }

  /* ============================================================
     OVERVIEW
     ============================================================ */
  function renderOverview(root) {
    const stats = CH.computeStats(APP.alerts);
    const lastScan = window.CH_DATA && window.CH_DATA.last_scan ? window.CH_DATA.last_scan : "moments ago";
    const enabledRules = APP.rules.filter(r => r.enabled).length;
    const gradeColor = stats.grade === "A" || stats.grade === "B" ? "var(--sev-low)" : stats.grade === "C" ? "var(--sev-med)" : "var(--sev-crit)";

    const sevData = [
      { label: "Critical", value: stats.bySeverity.CRITICAL, color: "var(--sev-crit)" },
      { label: "High", value: stats.bySeverity.HIGH, color: "var(--sev-high)" },
      { label: "Medium", value: stats.bySeverity.MEDIUM, color: "var(--sev-med)" },
      { label: "Low", value: stats.bySeverity.LOW, color: "var(--sev-low)" },
    ];
    const cloudData = Object.keys(CH.CLOUD_META).map(c => ({ label: CH.CLOUD_META[c].label, value: stats.byCloud[c] || 0, color: CH.CLOUD_META[c].color }));
    const topServices = Object.entries(stats.byService).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => ({ label: k || "—", value: v, color: "var(--accent)" }));

    root.innerHTML =
      '<div class="screen">' +
        '<div class="screen-head"><div>' +
          '<h1 class="screen-title">Security overview</h1>' +
          '<p class="screen-sub">Multi-cloud posture across AWS · GCP · Azure · last scan ' + esc(lastScan) + '</p>' +
        '</div><div class="head-actions">' +
          '<button class="btn ghost" data-act="export">' + icon("download", { size: 16 }) + 'Export report</button>' +
          '<a class="btn primary" href="' + (isPreview() ? "#scan" : "/scan") + '">' + icon("search", { size: 16 }) + 'Run scan</a>' +
        '</div></div>' +
        '<div class="kpi-row">' +
          '<div class="stat-tile score-tile"><div class="stat-tile-top"><span class="stat-label">Posture score</span>' + icon("shield", { size: 16, style: "color:" + gradeColor }) + '</div>' +
            '<div class="score-flex"><div class="stat-value" style="color:' + gradeColor + '">' + stats.score + '</div>' +
            '<div class="grade-badge" style="color:' + gradeColor + ';border-color:' + gradeColor + '55">' + stats.grade + '</div></div>' +
            '<div class="score-bar"><div class="score-fill" style="width:' + stats.score + '%;background:' + gradeColor + '"></div></div></div>' +
          statTile("Open findings", stats.total, "var(--text)", stats.totalAll + " total logged", "alert") +
          statTile("Critical", stats.bySeverity.CRITICAL, "var(--sev-crit)", "needs immediate action", "zap") +
          statTile("High", stats.bySeverity.HIGH, "var(--sev-high)", "triage within 24h", "arrowUp") +
          statTile("Active rules", enabledRules + "/" + APP.rules.length, "var(--accent)", "OWASP-tagged", "sliders") +
        '</div>' +
        '<div class="ov-grid"><div class="ov-left">' +
          '<div class="panel"><div class="panel-head"><div class="panel-title">' + icon("pulse", { size: 16 }) + 'Findings · last 48 hours</div><div class="panel-sub mono dim">2-hour buckets</div></div>' +
            '<div class="panel-body">' + CHART.area(stats.trend, { height: 120 }) + '</div></div>' +
          '<div class="ov-two">' +
            '<div class="panel"><div class="panel-head"><div class="panel-title">By severity</div></div>' +
              '<div class="panel-body donut-body">' + CHART.donut(sevData, { center: { value: stats.total, label: "OPEN" } }) +
                '<div class="legend">' + sevData.map(d =>
                  '<div class="legend-row"><span class="legend-dot" style="background:' + d.color + '"></span><span class="legend-label">' + d.label + '</span><span class="legend-val mono">' + d.value + '</span></div>').join("") +
                '</div></div></div>' +
            '<div class="panel"><div class="panel-head"><div class="panel-title">By cloud</div></div>' +
              '<div class="panel-body">' + CHART.hbars(cloudData) + '<div class="panel-divider"></div><div class="panel-subhead">Top services</div>' +
                (topServices.length ? CHART.hbars(topServices) : '<div class="dim" style="font-size:12.5px">No open findings</div>') + '</div></div>' +
          '</div></div>' +
          '<div class="ov-right">' + liveFeed() + '</div>' +
        '</div></div>';

    root.querySelector('[data-act="export"]').onclick = () => {
      const stats = CH.computeStats(APP.alerts);
      const report = { generated: new Date().toISOString(), posture_score: stats.score, grade: stats.grade, open_findings: stats.total, by_severity: stats.bySeverity, by_cloud: stats.byCloud, by_service: stats.byService };
      downloadAs(JSON.stringify(report, null, 2), "cloudhawk-report-" + stamp() + ".json", "application/json");
      toast("Posture report downloaded", "ok");
    };
    wireFeed(root);
  }

  function statTile(label, value, accent, sub, ic) {
    return '<div class="stat-tile"><div class="stat-tile-top"><span class="stat-label">' + label + '</span>' +
      (ic ? '<span style="color:' + (accent || "var(--text-dim)") + '">' + icon(ic, { size: 16 }) + '</span>' : "") + '</div>' +
      '<div class="stat-value" style="color:' + (accent || "var(--text)") + '">' + value + '</div>' +
      (sub ? '<div class="stat-sub">' + sub + '</div>' : "") + '</div>';
  }

  function liveFeed() {
    const recent = APP.alerts.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 14);
    const items = recent.map(a =>
      '<button class="feed-item' + (a._new ? " feed-new" : "") + '" data-alert="' + esc(a.id) + '">' + sevDot(a.severity) +
        '<div class="feed-main"><div class="feed-title">' + esc(a.title) + '</div>' +
          '<div class="feed-sub mono">' + cloudBadge(a.cloud) + '<span class="dim">' + esc(a.resource_id) + '</span></div></div>' +
        '<div class="feed-time mono dim">' + ago(a.ageMin) + '</div></button>').join("");
    return '<div class="panel feed-panel" id="live-feed"><div class="panel-head"><div class="panel-title"><span class="live-dot' + (APP.live ? " on" : "") + '"></span>Live alert stream</div>' +
      '<div class="panel-actions"><button class="chip-btn' + (APP.live ? " active" : "") + '" data-act="toggle-live">' + icon(APP.live ? "pulse" : "refresh", { size: 14 }) + (APP.live ? "Streaming" : "Paused") + '</button></div></div>' +
      '<div class="feed-list">' + (items || '<div class="empty">No recent alerts</div>') + '</div></div>';
  }
  function wireFeed(root) {
    const t = root.querySelector('[data-act="toggle-live"]');
    if (t) t.onclick = () => { APP.live = !APP.live; renderOverview(root); };
  }
  // allow the live engine to refresh just the feed
  APP.refreshFeed = () => {
    const root = document.getElementById("screen-root");
    if (root && root.dataset.active === "overview") {
      const fp = document.getElementById("live-feed");
      if (fp) { renderOverview(root); }
    }
  };

  /* ============================================================
     ALERTS
     ============================================================ */
  const aState = { q: new URLSearchParams(location.search).get("q") || "", sev: "ALL", cloud: "ALL", status: "OPEN", sortKey: "timestamp", sortDir: "desc", sel: new Set() };

  function alertsFiltered() {
    let rows = APP.alerts.filter(a => {
      if (aState.sev !== "ALL" && a.severity !== aState.sev) return false;
      if (aState.cloud !== "ALL" && a.cloud !== aState.cloud) return false;
      if (aState.status !== "ALL" && a.status !== aState.status) return false;
      if (aState.q) {
        const hay = (a.title + " " + a.resource_id + " " + a.rule_id + " " + a.service).toLowerCase();
        if (!hay.includes(aState.q.toLowerCase())) return false;
      }
      return true;
    });
    const { sortKey: key, sortDir: dir } = aState;
    rows.sort((a, b) => {
      let av, bv;
      if (key === "severity") { av = sevRank(a.severity); bv = sevRank(b.severity); }
      else if (key === "timestamp") { av = new Date(a.timestamp).getTime() || 0; bv = new Date(b.timestamp).getTime() || 0; }
      else { av = (a[key] || "").toString().toLowerCase(); bv = (b[key] || "").toString().toLowerCase(); }
      if (av < bv) return dir === "asc" ? -1 : 1;
      if (av > bv) return dir === "asc" ? 1 : -1;
      return 0;
    });
    return rows;
  }

  function renderAlerts(root) {
    aState.sel = new Set();
    const segSev = segmented([["ALL", "All"], ["CRITICAL", "Crit"], ["HIGH", "High"], ["MEDIUM", "Med"], ["LOW", "Low"]], aState.sev, "a-sev");
    root.innerHTML =
      '<div class="screen"><div class="screen-head"><div>' +
        '<h1 class="screen-title">Alerts</h1><p class="screen-sub" id="a-sub"></p></div></div>' +
        '<div class="toolbar">' +
          '<div class="search-box">' + icon("search", { size: 15 }) +
            '<input id="a-q" placeholder="Filter by title, resource, rule…" value="' + esc(aState.q) + '"/>' +
            '<button class="search-clear" id="a-clear" style="' + (aState.q ? "" : "display:none") + '">' + icon("x", { size: 13 }) + '</button></div>' +
          '<div class="toolbar-spacer"></div>' + segSev +
          select("a-cloud", aState.cloud, [["ALL", "All clouds"], ["aws", "AWS"], ["gcp", "GCP"], ["azure", "Azure"]]) +
          select("a-status", aState.status, [["OPEN", "Open"], ["ACKNOWLEDGED", "Ack'd"], ["RESOLVED", "Resolved"], ["ALL", "All"]]) +
        '</div>' +
        '<div id="a-results"></div></div>';

    const q = root.querySelector("#a-q");
    q.addEventListener("input", () => { aState.q = q.value; root.querySelector("#a-clear").style.display = q.value ? "" : "none"; updateAlerts(root); });
    root.querySelector("#a-clear").onclick = () => { aState.q = ""; q.value = ""; q.focus(); root.querySelector("#a-clear").style.display = "none"; updateAlerts(root); };
    root.querySelector("#a-cloud").onchange = e => { aState.cloud = e.target.value; updateAlerts(root); };
    root.querySelector("#a-status").onchange = e => { aState.status = e.target.value; updateAlerts(root); };
    wireSegmented(root, "a-sev", v => { aState.sev = v; updateAlerts(root); });
    updateAlerts(root);
  }

  function updateAlerts(root) {
    const rows = alertsFiltered();
    root.querySelector("#a-sub").textContent = rows.length + " of " + APP.alerts.length + " findings · live correlation against " + APP.rules.length + " rules";
    const allSel = rows.length > 0 && rows.every(a => aState.sel.has(a.id));
    const someSel = aState.sel.size > 0 && !allSel;

    const head = '<thead><tr>' +
      '<th class="col-check">' + checkbox(allSel, someSel, "a-all") + '</th>' +
      sortHead("severity", "Severity", 118) + sortHead("title", "Finding") +
      '<th style="width:92px">Cloud</th>' + sortHead("service", "Service", 110) +
      '<th style="width:200px">Resource</th>' + sortHead("timestamp", "Detected", 120) +
      '<th style="width:96px">Status</th></tr></thead>';

    const body = rows.map(a =>
      '<tr class="data-row' + (a._new ? " row-new" : "") + (APP.drawerId === a.id ? " row-active" : "") + (aState.sel.has(a.id) ? " row-sel" : "") + '" data-alert="' + esc(a.id) + '">' +
        '<td class="col-check" data-check="' + esc(a.id) + '">' + checkbox(aState.sel.has(a.id), false) + '</td>' +
        '<td>' + sevTag(a.severity) + '</td>' +
        '<td><div class="cell-title">' + esc(a.title) + '</div><div class="cell-rule mono">' + esc(a.rule_id) + '</div></td>' +
        '<td>' + cloudBadge(a.cloud) + '</td>' +
        '<td class="mono dim">' + esc(a.service) + '</td>' +
        '<td class="mono ellip" title="' + esc(a.resource_id) + '">' + esc(a.resource_id) + '</td>' +
        '<td class="mono dim nowrap">' + ago(a.ageMin) + '</td>' +
        '<td>' + statusPill(a.status) + '</td></tr>').join("");

    root.querySelector("#a-results").innerHTML =
      '<div class="table-wrap"><table class="data-table">' + head + '<tbody>' + body + '</tbody></table>' +
      (rows.length === 0 ? '<div class="empty">No findings match these filters.</div>' : "") + '</div>';

    // wire
    root.querySelectorAll("#a-results .th-inner[data-sort]").forEach(th => th.onclick = () => {
      const k = th.dataset.sort;
      if (aState.sortKey === k) aState.sortDir = aState.sortDir === "asc" ? "desc" : "asc";
      else { aState.sortKey = k; aState.sortDir = (k === "timestamp" || k === "severity") ? "desc" : "asc"; }
      updateAlerts(root);
    });
    root.querySelectorAll("#a-results .data-row").forEach(tr => tr.onclick = () => openDrawer(tr.dataset.alert));
    root.querySelectorAll("#a-results [data-check]").forEach(td => td.onclick = e => {
      e.stopPropagation(); const id = td.dataset.check;
      aState.sel.has(id) ? aState.sel.delete(id) : aState.sel.add(id); updateAlerts(root);
    });
    const allBox = root.querySelector('#a-results [data-allbox]');
    if (allBox) allBox.onclick = e => { e.stopPropagation(); aState.sel = allSel ? new Set() : new Set(rows.map(a => a.id)); updateAlerts(root); };

    renderBulk("alerts");
  }

  /* ============================================================
     TIMELINE
     ============================================================ */
  const tState = { cloud: "ALL" };
  function renderTimeline(root) {
    root.innerHTML =
      '<div class="screen"><div class="screen-head"><div>' +
        '<h1 class="screen-title">Event timeline</h1><p class="screen-sub">Chronological view of detections across the fleet</p></div>' +
        segmented([["ALL", "All"], ["aws", "AWS"], ["gcp", "GCP"], ["azure", "Azure"]], tState.cloud, "t-cloud") + '</div>' +
        '<div class="panel"><div class="panel-head"><div class="panel-title">' + icon("clock", { size: 16 }) + 'Detection volume · last 48h</div></div>' +
          '<div class="panel-body" id="t-chart"></div></div>' +
        '<div class="timeline" id="t-list"></div></div>';
    wireSegmented(root, "t-cloud", v => { tState.cloud = v; updateTimeline(root); });
    updateTimeline(root);
  }
  function updateTimeline(root) {
    const rows = APP.alerts.filter(a => tState.cloud === "ALL" || a.cloud === tState.cloud);
    const buckets = Array.from({ length: 24 }, (_, i) => ({ label: (46 - i * 2) + "h", sev: {} }));
    rows.forEach(a => {
      const idx = 23 - Math.min(23, Math.floor(a.ageMin / 120));
      if (idx >= 0) buckets[idx].sev[a.severity] = (buckets[idx].sev[a.severity] || 0) + 1;
    });
    root.querySelector("#t-chart").innerHTML = CHART.stackedCols(buckets);

    const sorted = rows.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 60);
    let html = "", lastDay = null;
    sorted.forEach(a => {
      const day = new Date(a.timestamp).toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" });
      const ds = new Date(a.timestamp).toDateString();
      if (ds !== lastDay) { html += '<div class="tl-day mono">' + day + '</div>'; lastDay = ds; }
      const tm = new Date(a.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
      html += '<button class="tl-item" data-alert="' + esc(a.id) + '">' +
        '<div class="tl-time mono dim">' + tm + '</div>' +
        '<div class="tl-rail">' + sevDot(a.severity, 10) + '<span class="tl-line"></span></div>' +
        '<div class="tl-card"><div class="tl-card-main"><span class="tl-title">' + esc(a.title) + '</span><span class="cell-rule mono">' + esc(a.rule_id) + '</span></div>' +
          '<div class="tl-card-meta">' + cloudBadge(a.cloud) + '<span class="mono dim">' + esc(a.resource_id) + '</span></div></div>' +
        sevTag(a.severity) + '</button>';
    });
    root.querySelector("#t-list").innerHTML = html || '<div class="empty">No events for this filter.</div>';
    root.querySelectorAll("#t-list .tl-item").forEach(b => b.onclick = () => openDrawer(b.dataset.alert));
  }

  /* ============================================================
     RULES
     ============================================================ */
  const rState = { q: "", sev: "ALL", cloud: "ALL", expanded: null, sel: new Set() };
  function rulesFiltered() {
    return APP.rules.filter(r => {
      if (rState.cloud !== "ALL" && r.cloud !== rState.cloud) return false;
      if (rState.sev !== "ALL" && r.severity !== rState.sev) return false;
      if (rState.q) {
        const hay = (r.id + " " + r.title + " " + r.owasp + " " + r.service).toLowerCase();
        if (!hay.includes(rState.q.toLowerCase())) return false;
      }
      return true;
    });
  }
  function renderRules(root) {
    rState.sel = new Set();
    root.innerHTML =
      '<div class="screen"><div class="screen-head"><div>' +
        '<h1 class="screen-title">Detection rules</h1><p class="screen-sub" id="r-sub"></p></div>' +
        '<button class="btn primary" data-act="new-rule">' + icon("zap", { size: 16 }) + 'New rule</button></div>' +
        '<div class="toolbar"><div class="search-box">' + icon("search", { size: 15 }) +
          '<input id="r-q" placeholder="Search rule id, title, OWASP…" value="' + esc(rState.q) + '"/>' +
          '<button class="search-clear" id="r-clear" style="' + (rState.q ? "" : "display:none") + '">' + icon("x", { size: 13 }) + '</button></div>' +
          '<div class="toolbar-spacer"></div>' + segmented([["ALL", "All"], ["CRITICAL", "Crit"], ["HIGH", "High"], ["MEDIUM", "Med"], ["LOW", "Low"]], rState.sev, "r-sev") +
          select("r-cloud", rState.cloud, [["ALL", "All clouds"], ["aws", "AWS"], ["gcp", "GCP"], ["azure", "Azure"]]) + '</div>' +
        '<div id="r-results"></div></div>';
    const q = root.querySelector("#r-q");
    q.addEventListener("input", () => { rState.q = q.value; root.querySelector("#r-clear").style.display = q.value ? "" : "none"; updateRules(root); });
    root.querySelector("#r-clear").onclick = () => { rState.q = ""; q.value = ""; q.focus(); root.querySelector("#r-clear").style.display = "none"; updateRules(root); };
    root.querySelector("#r-cloud").onchange = e => { rState.cloud = e.target.value; updateRules(root); };
    root.querySelector('[data-act="new-rule"]').onclick = () => showNewRuleModal(root);
    wireSegmented(root, "r-sev", v => { rState.sev = v; updateRules(root); });
    updateRules(root);
  }
  function updateRules(root) {
    const rows = rulesFiltered();
    const enabledCount = APP.rules.filter(r => r.enabled).length;
    root.querySelector("#r-sub").textContent = enabledCount + " of " + APP.rules.length + " rules active · OWASP Top 10 mapped";
    const hitCount = {};
    APP.alerts.forEach(a => { if (a.status === "OPEN") hitCount[a.rule_id] = (hitCount[a.rule_id] || 0) + 1; });
    const allSel = rows.length > 0 && rows.every(r => rState.sel.has(r.id));
    const someSel = rState.sel.size > 0 && !allSel;

    const head = '<thead><tr><th class="col-check">' + checkbox(allSel, someSel, "r-all") + '</th>' +
      '<th style="width:120px">Rule ID</th><th>Rule</th><th style="width:92px">Cloud</th>' +
      '<th style="width:118px">Severity</th><th style="width:230px">OWASP</th><th style="width:90px">Findings</th><th style="width:70px">Active</th></tr></thead>';

    const body = rows.map(r => {
      const open = rState.expanded === r.id;
      let h = '<tr class="data-row' + (rState.sel.has(r.id) ? " row-sel" : "") + (r.enabled ? "" : " row-off") + '" data-rule="' + esc(r.id) + '">' +
        '<td class="col-check" data-rcheck="' + esc(r.id) + '">' + checkbox(rState.sel.has(r.id), false) + '</td>' +
        '<td class="mono accent-text">' + esc(r.id) + '</td>' +
        '<td><div class="cell-title">' + esc(r.title) + icon(open ? "chevronDown" : "chevronRight", { size: 13, style: "color:var(--text-dim);margin-left:6px" }) + '</div>' +
          '<div class="cell-rule">' + esc(r.description) + '</div></td>' +
        '<td>' + cloudBadge(r.cloud) + '</td><td>' + sevTag(r.severity) + '</td>' +
        '<td class="owasp-cell">' + esc(r.owasp) + '</td>' +
        '<td class="mono" style="color:' + (hitCount[r.id] ? "var(--sev-high)" : "var(--text-dim)") + '">' + (hitCount[r.id] || 0) + '</td>' +
        '<td data-rtoggle="' + esc(r.id) + '">' + toggle(r.enabled) + '</td></tr>';
      if (open) {
        h += '<tr class="expand-row"><td></td><td colspan="7"><div class="rule-detail">' +
          '<div class="rd-block"><div class="rd-label">Condition</div><pre class="code-block inline"><code>' + esc(r.condition) + '</code></pre></div>' +
          '<div class="rd-block"><div class="rd-label">' + icon("zap", { size: 13 }) + ' Remediation</div><div class="dr-remedy">' + esc(r.remediation) + '</div></div>' +
          '</div></td></tr>';
      }
      return h;
    }).join("");

    root.querySelector("#r-results").innerHTML =
      '<div class="table-wrap"><table class="data-table rules-table">' + head + '<tbody>' + body + '</tbody></table>' +
      (rows.length === 0 ? '<div class="empty">No rules match these filters.</div>' : "") + '</div>';

    root.querySelectorAll("#r-results .data-row").forEach(tr => tr.onclick = () => {
      rState.expanded = rState.expanded === tr.dataset.rule ? null : tr.dataset.rule; updateRules(root);
    });
    root.querySelectorAll("#r-results [data-rcheck]").forEach(td => td.onclick = e => {
      e.stopPropagation(); const id = td.dataset.rcheck; rState.sel.has(id) ? rState.sel.delete(id) : rState.sel.add(id); updateRules(root);
    });
    root.querySelectorAll("#r-results [data-rtoggle]").forEach(td => td.onclick = e => {
      e.stopPropagation(); APP.onToggleRule(td.dataset.rtoggle); updateRules(root);
    });
    const allBox = root.querySelector('#r-results [data-allbox]');
    if (allBox) allBox.onclick = e => { e.stopPropagation(); rState.sel = allSel ? new Set() : new Set(rows.map(r => r.id)); updateRules(root); };

    renderBulk("rules");
  }

  /* ============================================================
     NEW RULE MODAL
     ============================================================ */
  function mField(label, id, type, placeholder, required) {
    const isTA = type === "textarea";
    const field = isTA
      ? '<textarea id="' + id + '" class="select" rows="3" style="width:100%;font-family:inherit;resize:vertical" placeholder="' + esc(placeholder || "") + '"></textarea>'
      : '<input id="' + id + '" type="text" class="select" style="width:100%" placeholder="' + esc(placeholder || "") + '">';
    return '<div><label class="dr-k" style="display:block;margin-bottom:6px">' + label + (required ? ' <span style="color:var(--sev-crit)">*</span>' : "") + '</label>' + field + '</div>';
  }
  function showNewRuleModal(root) {
    const o = overlayRoot();
    const sevOpts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => '<option value="' + s + '">' + s + '</option>').join("");
    const owaspOpts = [
      "A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures",
      "A03:2021 Injection", "A04:2021 Insecure Design", "A05:2021 Security Misconfiguration",
      "A06:2021 Vulnerable Components", "A07:2021 Authentication Failures",
      "A08:2021 Software and Data Integrity", "A09:2021 Logging Failures", "A10:2021 SSRF",
    ].map(v => '<option value="' + v + '">' + v + '</option>').join("");
    o.innerHTML =
      '<div style="position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:800" id="d-scrim">' +
      '<div style="background:var(--panel);border:1px solid var(--line);border-radius:10px;width:560px;max-width:calc(100vw - 32px);max-height:90vh;overflow-y:auto;display:flex;flex-direction:column" onclick="event.stopPropagation()">' +
      '<div class="drawer-head"><div class="drawer-head-top">' +
        '<h2 class="drawer-title" style="font-size:16px;margin:0">New detection rule</h2>' +
        '<div style="flex:1"></div><button class="icon-btn" id="m-close">' + icon("x", { size: 18 }) + '</button></div></div>' +
      '<div style="display:flex;flex-direction:column;gap:14px;padding:20px 24px">' +
        mField("Rule ID", "m-id", "text", "AWS_EC2_099", true) +
        mField("Title", "m-title", "text", "Publicly exposed resource", true) +
        mField("Description", "m-desc", "textarea", "Detects publicly accessible resources that may expose sensitive data.") +
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">' +
          mField("Service", "m-service", "text", "EC2") +
          '<div><label class="dr-k" style="display:block;margin-bottom:6px">Severity</label>' +
            '<select id="m-severity" class="select" style="width:100%">' + sevOpts + '</select></div>' +
        '</div>' +
        '<div><label class="dr-k" style="display:block;margin-bottom:6px">OWASP category</label>' +
          '<select id="m-owasp" class="select" style="width:100%">' + owaspOpts + '</select></div>' +
        mField("Condition", "m-condition", "textarea", 'event_type == "AuthorizeSecurityGroupIngress" and cidr == "0.0.0.0/0"') +
        mField("Remediation", "m-remediation", "textarea", "Restrict security group ingress rules to known CIDR ranges.") +
      '</div>' +
      '<div class="drawer-foot">' +
        '<button class="btn primary" id="m-submit">' + icon("zap", { size: 15 }) + 'Add rule</button>' +
        '<button class="btn ghost" id="m-cancel">Cancel</button>' +
      '</div></div></div>';
    const close = () => { o.innerHTML = ""; };
    document.getElementById("d-scrim").onclick = close;
    document.getElementById("m-close").onclick = close;
    document.getElementById("m-cancel").onclick = close;
    document.getElementById("m-submit").onclick = () => submitNewRule(root, close);
  }
  function submitNewRule(root, close) {
    const val = id => (document.getElementById(id) || {}).value || "";
    const rule = {
      id: val("m-id").trim(),
      title: val("m-title").trim(),
      description: val("m-desc").trim(),
      service: (val("m-service").trim().toUpperCase()) || "GENERIC",
      severity: val("m-severity"),
      owasp: val("m-owasp"),
      condition: val("m-condition").trim(),
      remediation: val("m-remediation").trim(),
    };
    if (!rule.id || !rule.title) { toast("Rule ID and Title are required", "err"); return; }
    apiPost("/api/rules/add", rule).then(res => {
      if (!res || res.status === "error") { toast((res && res.message) || "Failed to add rule", "err"); return; }
      const cloud = rule.id.startsWith("AZ") ? "azure" : rule.id.startsWith("GCP") ? "gcp" : "aws";
      const newRule = Object.assign({ enabled: true, cloud }, rule);
      APP.rules = [...APP.rules, newRule];
      APP.ruleMap[rule.id] = newRule;
      close();
      updateRules(root);
      toast("Rule " + rule.id + " added", "ok");
    });
  }

  /* ============================================================
     COMPLIANCE
     ============================================================ */
  function renderCompliance(root) {
    const cats = CH.computeCompliance(APP.rules, APP.alerts);
    const totalFindings = cats.reduce((s, c) => s + c.findings, 0);
    const clean = cats.filter(c => c.findings === 0).length;
    const cards = cats.map(c => {
      const code = c.owasp.split(" ")[0];
      const name = c.owasp.replace(code, "").trim() || c.owasp;
      const pass = c.findings === 0;
      const sevColor = c.critical > 0 ? "var(--sev-crit)" : c.findings > 0 ? "var(--sev-high)" : "var(--sev-low)";
      return '<div class="comp-card' + (pass ? " pass" : "") + '"><div class="comp-top"><span class="comp-code mono">' + esc(code) + '</span>' +
        '<span class="comp-status" style="color:' + sevColor + ';border-color:' + sevColor + '55">' + (pass ? "PASS" : c.findings + " open") + '</span></div>' +
        '<div class="comp-name">' + esc(name) + '</div><div class="comp-stats">' +
          '<div class="comp-stat"><span class="mono">' + c.rules + '</span><span class="comp-stat-l">rules</span></div>' +
          '<div class="comp-stat"><span class="mono" style="color:' + sevColor + '">' + c.findings + '</span><span class="comp-stat-l">findings</span></div>' +
          '<div class="comp-stat"><span class="mono" style="color:' + (c.critical ? "var(--sev-crit)" : "var(--text-dim)") + '">' + c.critical + '</span><span class="comp-stat-l">critical</span></div></div>' +
        '<div class="comp-bar"><div class="comp-bar-fill" style="width:' + (pass ? "100%" : Math.max(8, 100 - c.findings * 8) + "%") + ';background:' + sevColor + '"></div></div></div>';
    }).join("");

    root.innerHTML =
      '<div class="screen"><div class="screen-head"><div>' +
        '<h1 class="screen-title">Compliance · OWASP Top 10</h1><p class="screen-sub">Coverage and open findings mapped to the 2021 OWASP categories</p></div>' +
        '<button class="btn ghost" data-act="export-pdf">' + icon("download", { size: 16 }) + 'Export PDF</button></div>' +
        '<div class="kpi-row k4">' +
          statTile("Categories covered", cats.length, "var(--accent)", "OWASP 2021", "scale") +
          statTile("Passing", clean, "var(--sev-low)", "no open findings", "check") +
          statTile("Open findings", totalFindings, "var(--sev-high)", "across all categories", "alert") +
          statTile("Rules mapped", APP.rules.length, "var(--text)", "100% tagged", "sliders") +
        '</div><div class="comp-grid">' + cards + '</div></div>';
    root.querySelector('[data-act="export-pdf"]').onclick = () => {
      const cats = CH.computeCompliance(APP.rules, APP.alerts);
      downloadAs(complianceToCSV(cats), "cloudhawk-compliance-" + stamp() + ".csv", "text/csv");
      toast("Compliance report downloaded (CSV)", "ok");
    };
  }

  /* ============================================================
     DRAWER
     ============================================================ */
  function overlayRoot() {
    let o = document.getElementById("ch-overlay");
    if (!o) { o = document.createElement("div"); o.id = "ch-overlay"; document.body.appendChild(o); }
    return o;
  }
  function openDrawer(id) {
    APP.drawerId = id;
    const a = APP.alerts.find(x => x.id === id);
    if (!a) return;
    // reflect deep-link in URL (production)
    if (!isPreview() && history.replaceState) {
      const u = new URL(location.href); u.searchParams.set("alert", id); history.replaceState({}, "", u);
    }
    const json = JSON.stringify(a.raw_event || {}, null, 2);
    const foot =
      (a.status !== "RESOLVED" ? '<button class="btn primary" data-d="resolve">' + icon("shield", { size: 16 }) + 'Resolve</button>' : "") +
      (a.status === "OPEN" ? '<button class="btn ghost" data-d="ack">' + icon("check", { size: 16 }) + 'Acknowledge</button>' : "") +
      '<button class="btn ghost" data-d="suppress">' + icon("bell", { size: 16 }) + 'Suppress rule</button>' +
      '<div style="flex:1"></div>' +
      '<a class="btn ghost" href="' + consoleUrl(a) + '" target="_blank" rel="noopener">' + icon("external", { size: 16 }) + 'Open in console</a>';

    overlayRoot().innerHTML =
      '<div class="drawer-scrim" id="d-scrim"><aside class="drawer" id="d-aside">' +
        '<div class="drawer-head"><div class="drawer-head-top">' + sevTag(a.severity, true) + cloudBadge(a.cloud, true) + statusPill(a.status) +
          '<div style="flex:1"></div><button class="icon-btn" data-d="close">' + icon("x", { size: 18 }) + '</button></div>' +
          '<h2 class="drawer-title">' + esc(a.title) + '</h2>' +
          '<div class="drawer-meta mono">' + esc(a.rule_id) + ' · ' + esc(a.id) + ' · ' + fmtTime(a.timestamp) + '</div></div>' +
        '<div class="drawer-body">' +
          '<section class="dr-sec"><div class="dr-label">Description</div><p class="dr-text">' + esc(a.description) + '</p></section>' +
          '<section class="dr-grid">' +
            kv("Service", a.service, true) + kv("Region", a.region, true) +
            kv("Source", a.source, true) + kv("Event type", a.event_type, true) +
            kv("Resource", a.resource_id, true, true) + kv("OWASP", a.owasp, false, true) +
          '</section>' +
          '<section class="dr-sec"><div class="dr-label">' + icon("zap", { size: 14 }) + ' Remediation</div><div class="dr-remedy">' + esc(a.remediation || "No remediation provided.") + '</div></section>' +
          '<section class="dr-sec"><div class="dr-label">' + icon("doc", { size: 14 }) + ' Raw event</div><pre class="code-block"><code>' + esc(json) + '</code></pre></section>' +
        '</div><div class="drawer-foot">' + foot + '</div></aside></div>';

    const close = () => closeDrawer();
    document.getElementById("d-scrim").onclick = close;
    document.getElementById("d-aside").onclick = e => e.stopPropagation();
    overlayRoot().querySelector('[data-d="close"]').onclick = close;
    const fb = overlayRoot().querySelector('[data-d="resolve"]'); if (fb) fb.onclick = () => { APP.onResolve([id]); close(); refreshActive(); };
    const fa = overlayRoot().querySelector('[data-d="ack"]'); if (fa) fa.onclick = () => { APP.onAck([id]); openDrawer(id); refreshActive(); };
    const fs = overlayRoot().querySelector('[data-d="suppress"]'); if (fs) fs.onclick = () => { APP.onSuppress([id]); openDrawer(id); refreshActive(); };
    document.addEventListener("keydown", escClose);
  }
  function escClose(e) { if (e.key === "Escape") closeDrawer(); }
  function closeDrawer() {
    APP.drawerId = null;
    overlayRoot().innerHTML = "";
    document.removeEventListener("keydown", escClose);
    if (!isPreview() && history.replaceState) { const u = new URL(location.href); u.searchParams.delete("alert"); history.replaceState({}, "", u); }
    refreshActive();
  }
  function kv(k, v, mono, full) {
    return '<div class="dr-kv' + (full ? " full" : "") + '"><span class="dr-k">' + k + '</span><span class="dr-v' + (mono ? " mono" : "") + '">' + esc(v || "—") + '</span></div>';
  }
  APP.openDrawer = openDrawer;

  /* ============================================================
     BULK BAR
     ============================================================ */
  function renderBulk(kind) {
    const sel = kind === "alerts" ? aState.sel : rState.sel;
    const o = overlayBulk();
    if (!sel.size) { o.innerHTML = ""; return; }
    let actions;
    if (kind === "alerts") {
      actions = '<button class="btn ghost" data-b="ack">' + icon("check", { size: 15 }) + 'Acknowledge</button>' +
        '<button class="btn ghost" data-b="resolve">' + icon("shield", { size: 15 }) + 'Resolve</button>' +
        '<button class="btn ghost" data-b="suppress">' + icon("bell", { size: 15 }) + 'Suppress rule</button>' +
        '<button class="btn ghost" data-b="export">' + icon("download", { size: 15 }) + 'Export</button>';
    } else {
      actions = '<button class="btn ghost" data-b="enable">' + icon("check", { size: 15 }) + 'Enable</button>' +
        '<button class="btn ghost" data-b="disable">' + icon("bell", { size: 15 }) + 'Disable</button>' +
        '<button class="btn ghost" data-b="export">' + icon("download", { size: 15 }) + 'Export YAML</button>';
    }
    o.innerHTML = '<div class="bulk-bar"><div class="bulk-count"><span class="mono">' + sel.size + '</span> selected</div>' +
      '<div class="bulk-actions">' + actions + '</div><button class="bulk-clear" data-b="clear">' + icon("x", { size: 15 }) + '</button></div>';
    const ids = [...sel];
    const root = document.getElementById("screen-root");
    const reRender = () => kind === "alerts" ? updateAlerts(root) : updateRules(root);
    o.querySelectorAll("[data-b]").forEach(btn => btn.onclick = () => {
      const act = btn.dataset.b;
      if (act === "clear") { sel.clear(); reRender(); return; }
      if (kind === "alerts") {
        if (act === "ack") APP.onAck(ids); else if (act === "resolve") APP.onResolve(ids);
        else if (act === "suppress") APP.onSuppress(ids);
        else if (act === "export") {
          const sel = APP.alerts.filter(a => ids.includes(a.id));
          downloadAs(alertsToCSV(sel), "cloudhawk-alerts-" + stamp() + ".csv", "text/csv");
          toast("Exported " + ids.length + " finding(s) as CSV", "ok");
        }
      } else {
        APP.onBulkRules(ids, act === "export" ? "export" : act);
      }
      sel.clear(); reRender();
    });
  }
  function overlayBulk() {
    let o = document.getElementById("ch-bulk");
    if (!o) { o = document.createElement("div"); o.id = "ch-bulk"; document.body.appendChild(o); }
    return o;
  }

  /* ============================================================
     small builders
     ============================================================ */
  function segmented(opts, value, group) {
    return '<div class="segmented" data-seg="' + group + '">' + opts.map(o =>
      '<button class="seg-btn' + (o[0] === value ? " active" : "") + '" data-val="' + o[0] + '">' + o[1] + '</button>').join("") + '</div>';
  }
  function wireSegmented(root, group, cb) {
    const seg = root.querySelector('[data-seg="' + group + '"]');
    if (!seg) return;
    seg.querySelectorAll(".seg-btn").forEach(b => b.onclick = () => {
      seg.querySelectorAll(".seg-btn").forEach(x => x.classList.remove("active"));
      b.classList.add("active"); cb(b.dataset.val);
    });
  }
  function select(id, value, opts) {
    return '<select class="select" id="' + id + '">' + opts.map(o =>
      '<option value="' + o[0] + '"' + (o[0] === value ? " selected" : "") + '>' + o[1] + '</option>').join("") + '</select>';
  }
  function sortHead(key, label, w) {
    const active = aState.sortKey === key;
    const arrow = active ? icon(aState.sortDir === "asc" ? "arrowUp" : "arrowDown", { size: 12, stroke: 2.2 }) : "";
    return '<th' + (w ? ' style="width:' + w + 'px"' : "") + (active ? ' class="sorted"' : "") + '><span class="th-inner" data-sort="' + key + '">' + label + arrow + '</span></th>';
  }
  function checkbox(checked, indet, allId) {
    const cls = "check " + (checked ? "checked" : (indet ? "indet" : ""));
    const inner = checked ? icon("check", { size: 13, stroke: 2.4 }) : (indet ? '<span class="check-dash"></span>' : "");
    return '<span class="' + cls + '"' + (allId ? ' data-allbox="' + allId + '"' : "") + '>' + inner + '</span>';
  }
  function toggle(on) { return '<span class="toggle sm' + (on ? " on" : "") + '"><span class="toggle-knob"></span></span>'; }

  /* refresh whichever screen is active (after a mutation from the drawer) */
  function refreshActive() {
    const root = document.getElementById("screen-root");
    if (!root) return;
    const s = root.dataset.active;
    if (SCREENS[s]) {
      // keep filter state; re-render results only where possible
      if (s === "alerts") updateAlerts(root);
      else if (s === "rules") updateRules(root);
      else if (s === "timeline") updateTimeline(root);
      else SCREENS[s](root);
    }
  }
  APP.refreshActive = refreshActive;

  const SCREENS = {
    overview: renderOverview,
    alerts: renderAlerts,
    timeline: renderTimeline,
    rules: renderRules,
    compliance: renderCompliance,
  };
  window.SCREENS = SCREENS;
})();
