/* ============================================================
   CloudHawk Console — core (plain JS, no framework)
   Helpers, icon set, string-returning components, and the data
   layer that normalizes the REAL CloudHawk shapes:
     - alerts nest fields under `log_excerpt`
     - rules have no `cloud` / `enabled`
   Exposes window.CH
   ============================================================ */
(function () {
  "use strict";

  /* ---------- icon set (1.7px stroke line glyphs) ---------- */
  const ICON_PATHS = {
    grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
    alert: "M12 3l9 16H3zM12 10v4M12 17h.01",
    pulse: "M3 12h4l2 6 4-14 2 8h6",
    shield: "M12 3l7 3v5c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6z",
    scale: "M12 4v16M6 8h12M5 8l-2 6h6zM19 8l-2 6h6zM8 20h8",
    search: "M11 5a6 6 0 100 12 6 6 0 000-12zM20 20l-4-4",
    bell: "M6 9a6 6 0 0112 0c0 5 2 6 2 6H4s2-1 2-6M10 21h4",
    clock: "M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z",
    filter: "M3 5h18l-7 8v5l-4 2v-7z",
    chevronDown: "M6 9l6 6 6-6",
    chevronRight: "M9 6l6 6-6 6",
    x: "M6 6l12 12M18 6L6 18",
    check: "M5 12l5 5 9-11",
    refresh: "M20 11a8 8 0 10-1 5M20 5v6h-6",
    sliders: "M4 7h10M18 7h2M4 17h2M10 17h10M14 5v4M8 15v4",
    download: "M12 4v10M8 11l4 4 4-4M5 19h14",
    external: "M14 5h5v5M19 5l-8 8M11 5H6a1 1 0 00-1 1v12a1 1 0 001 1h12a1 1 0 001-1v-5",
    cloud: "M7 18a4 4 0 01-.5-7.97A6 6 0 0118 9a3.5 3.5 0 01-.5 9z",
    hawk: "M3 11l9-6 9 6-4 2 2 6-7-4-7 4 2-6z",
    dot: "M12 12h.01",
    arrowUp: "M12 19V5M6 11l6-6 6 6",
    arrowDown: "M12 5v14M6 13l6 6 6-6",
    doc: "M7 3h7l4 4v14H7zM14 3v4h4",
    lock: "M7 11V8a5 5 0 0110 0v3M5 11h14v9H5z",
    zap: "M13 3L5 13h6l-2 8 8-10h-6z",
    cog: "M12 9a3 3 0 100 6 3 3 0 000-6zM19 12a7 7 0 00-.1-1l2-1.6-2-3.4-2.4 1a7 7 0 00-1.7-1l-.4-2.5h-4l-.4 2.5a7 7 0 00-1.7 1l-2.4-1-2 3.4 2 1.6a7 7 0 000 2l-2 1.6 2 3.4 2.4-1a7 7 0 001.7 1l.4 2.5h4l.4-2.5a7 7 0 001.7-1l2.4 1 2-3.4-2-1.6a7 7 0 00.1-1z",
    mail: "M3 6h18v12H3zM3 7l9 6 9-6",
    slack: "M6 14a2 2 0 11-2-2h2zM8 14a2 2 0 014 0v5a2 2 0 11-4 0zM10 6a2 2 0 112 2h-2zM10 8a2 2 0 010 4H5a2 2 0 010-4zM18 10a2 2 0 112 2h-2zM16 10a2 2 0 01-4 0V5a2 2 0 014 0zM14 18a2 2 0 11-2-2h2zM14 16a2 2 0 010-4h5a2 2 0 010 4z",
    menu: "M4 6h16M4 12h16M4 18h16",
    play: "M7 5l11 7-11 7z",
  };

  function icon(name, opts) {
    opts = opts || {};
    const size = opts.size || 18;
    const stroke = opts.stroke || 1.7;
    const fill = opts.fill ? "currentColor" : "none";
    const cls = opts.className ? ' class="' + opts.className + '"' : "";
    const st = opts.style ? ' style="' + opts.style + '"' : "";
    const d = ICON_PATHS[name] || ICON_PATHS.dot;
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="' + stroke +
      '" stroke-linecap="round" stroke-linejoin="round"' + cls + st + '><path d="' + d + '" fill="' + fill + '"/></svg>';
  }

  /* ---------- escaping ---------- */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  /* ---------- severity / cloud / status ---------- */
  const SEV_STYLE = {
    CRITICAL: { c: "var(--sev-crit)", bg: "var(--sev-crit-bg)" },
    HIGH:     { c: "var(--sev-high)", bg: "var(--sev-high-bg)" },
    MEDIUM:   { c: "var(--sev-med)",  bg: "var(--sev-med-bg)" },
    LOW:      { c: "var(--sev-low)",  bg: "var(--sev-low-bg)" },
  };
  function sevRank(s) { return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[s] || 0; }

  function sevTag(sev, solid) {
    const s = SEV_STYLE[sev] || SEV_STYLE.LOW;
    const color = solid ? "#0b0d12" : s.c;
    const bg = solid ? s.c : s.bg;
    const bc = solid ? "transparent" : s.c + "55";
    const dot = solid ? "#0b0d12" : s.c;
    return '<span class="sev-tag" style="color:' + color + ';background:' + bg + ';border-color:' + bc +
      '"><span class="sev-dot" style="background:' + dot + '"></span>' + esc(sev) + '</span>';
  }
  function sevDot(sev, size) {
    const s = SEV_STYLE[sev] || SEV_STYLE.LOW;
    size = size || 8;
    return '<span style="width:' + size + 'px;height:' + size + 'px;border-radius:99px;background:' + s.c +
      ';display:inline-block;box-shadow:0 0 8px ' + s.c + '66"></span>';
  }

  const CLOUD_META = {
    aws:   { label: "AWS",          short: "AWS", color: "#FF9D2E" },
    gcp:   { label: "Google Cloud", short: "GCP", color: "#5B9BFF" },
    azure: { label: "Azure",        short: "AZ",  color: "#3DC2D6" },
  };
  function cloudBadge(cloud, withLabel) {
    const m = CLOUD_META[cloud] || CLOUD_META.aws;
    return '<span class="cloud-badge" style="color:' + m.color + ';border-color:' + m.color + '44;background:' + m.color + '14">' +
      m.short + (withLabel ? " · " + m.label : "") + '</span>';
  }

  const STATUS_MAP = {
    OPEN: { c: "var(--accent)", t: "Open" },
    ACKNOWLEDGED: { c: "var(--text-dim)", t: "Ack'd" },
    RESOLVED: { c: "var(--sev-low)", t: "Resolved" },
  };
  function statusPill(status) {
    const s = STATUS_MAP[status] || STATUS_MAP.OPEN;
    return '<span class="status-pill" style="color:' + s.c + ';border-color:' + s.c + '44">' + s.t + '</span>';
  }

  /* ---------- time formatting ---------- */
  function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return String(iso || "");
    return d.toLocaleString("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
  }
  function ago(min) {
    if (min == null || isNaN(min)) return "";
    if (min < 1) return "just now";
    if (min < 60) return min + "m ago";
    const h = Math.floor(min / 60);
    if (h < 24) return h + "h ago";
    return Math.floor(h / 24) + "d ago";
  }
  function ageMinOf(iso) {
    const t = new Date(iso).getTime();
    if (isNaN(t)) return 0;
    return Math.max(0, Math.round((Date.now() - t) / 60000));
  }

  /* ---------- cloud derivation (real rules/alerts carry no `cloud`) ---------- */
  function deriveCloud(o) {
    const src = (o.source || "").toUpperCase();
    const rid = (o.rule_id || o.id || "").toUpperCase();
    if (src.startsWith("GCP") || rid.startsWith("GCP")) return "gcp";
    if (src.startsWith("AZURE") || src.startsWith("AZ_") || rid.startsWith("AZ-") || rid.startsWith("AZ")) return "azure";
    return "aws";
  }

  /* ---------- stable id (djb2 over rule_id|resource_id|timestamp) ----------
     Array-index ids are unstable across reloads/polls, which breaks both
     status persistence and ?alert= deep-links. A composite hash is stable as
     long as the finding's identity fields persist. */
  function hashId(s) {
    let h = 5381;
    for (let i = 0; i < s.length; i++) { h = ((h << 5) + h) + s.charCodeAt(i); h |= 0; }
    return "AL-" + (h >>> 0).toString(36);
  }

  /* ---------- normalization ---------- */
  // Build an owasp lookup from the rules so alerts can inherit it.
  function normalizeRules(rawRules) {
    return (rawRules || []).map(r => {
      const cloud = deriveCloud(r);
      const enabled = r.enabled === false ? false : (r.status === "disabled" ? false : true);
      return {
        id: r.id, title: r.title || r.id, description: r.description || "",
        service: r.service || "", owasp: r.owasp || "", condition: r.condition || "",
        severity: (r.severity || "LOW").toUpperCase(), remediation: r.remediation || "",
        cloud, enabled,
      };
    });
  }

  function normalizeAlerts(rawAlerts, ruleMap) {
    ruleMap = ruleMap || {};
    return (rawAlerts || []).map((a, i) => {
      const log = a.log_excerpt || {};
      const source = a.source || log.source || "";
      const resource_id = a.resource_id || log.resource_id || "";
      const event_type = a.event_type || log.event_type || "";
      const region = a.region || log.region || "";
      const raw_event = a.raw_event || log.raw_event || log || {};
      const rule = ruleMap[a.rule_id] || {};
      const ts = a.timestamp || log.timestamp || "";
      const rid = a.rule_id || rule.id || "";
      const stable = (rid || resource_id || ts) ? hashId(rid + "|" + resource_id + "|" + ts) : "AL-" + i;
      const o = {
        id: a.id || stable,
        timestamp: ts,
        rule_id: rid,
        title: a.title || rule.title || "Security finding",
        description: a.description || log.description || rule.description || "",
        severity: (a.severity || log.severity || rule.severity || "LOW").toUpperCase(),
        remediation: a.remediation || rule.remediation || "",
        service: a.service || rule.service || "",
        owasp: a.owasp || rule.owasp || "",
        status: (a.status || "OPEN").toUpperCase(),
        resource_id, source, event_type, region, raw_event,
        source_for_cloud: source,
        _new: !!a._new,
      };
      o.cloud = deriveCloud({ source, rule_id: o.rule_id });
      o.ageMin = ageMinOf(o.timestamp);
      return o;
    });
  }

  /* ---------- derived stats (mirrors app.py weighting spirit) ---------- */
  function computeStats(alerts) {
    const open = alerts.filter(a => a.status === "OPEN");
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const byCloud = { aws: 0, gcp: 0, azure: 0 };
    const byService = {};
    open.forEach(a => {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
      byCloud[a.cloud] = (byCloud[a.cloud] || 0) + 1;
      byService[a.service] = (byService[a.service] || 0) + 1;
    });
    let score = 100 - bySeverity.CRITICAL * 1.8 - bySeverity.HIGH * 0.7 - bySeverity.MEDIUM * 0.3 - bySeverity.LOW * 0.08;
    score = Math.max(0, Math.round(score));
    const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
    const trend = new Array(24).fill(0);
    alerts.forEach(a => {
      const bucket = 23 - Math.min(23, Math.floor(a.ageMin / 120));
      if (bucket >= 0) trend[bucket]++;
    });
    return { total: open.length, totalAll: alerts.length, bySeverity, byCloud, byService, score, grade, trend };
  }

  function computeCompliance(rules, alerts) {
    const cats = {};
    rules.forEach(r => {
      const key = r.owasp || "Uncategorized";
      if (!cats[key]) cats[key] = { owasp: key, rules: 0, findings: 0, critical: 0 };
      cats[key].rules++;
    });
    alerts.filter(a => a.status === "OPEN").forEach(a => {
      const key = a.owasp || "Uncategorized";
      if (!cats[key]) cats[key] = { owasp: key, rules: 0, findings: 0, critical: 0 };
      cats[key].findings++;
      if (a.severity === "CRITICAL") cats[key].critical++;
    });
    return Object.values(cats).sort((a, b) => b.findings - a.findings);
  }

  /* ---------- live alert synthesis (preview flourish) ---------- */
  let liveCounter = 90000;
  function makeLiveAlert(pool) {
    if (!pool || !pool.length) return null;
    const open = pool.filter(a => ["CRITICAL", "HIGH", "MEDIUM"].includes(a.severity));
    const base = (open.length ? open : pool)[Math.floor(Math.random() * (open.length ? open.length : pool.length))];
    liveCounter++;
    return Object.assign({}, base, {
      id: "AL-" + liveCounter,
      timestamp: new Date().toISOString(),
      ageMin: 0,
      status: "OPEN",
      _new: true,
    });
  }

  /* ---------- data acquisition ----------
     Priority:
       1. window.CH_DATA  (server-injected via Jinja {{ ...|tojson }})
       2. window.CH_MOCK()  (preview harness; returns RAW shapes)
       3. fetch /api/alerts + /api/rules  (live Flask, unauthenticated routes)
  */
  async function load() {
    let rawAlerts = [], rawRules = [];
    if (window.CH_DATA) {
      rawAlerts = window.CH_DATA.alerts || [];
      rawRules = window.CH_DATA.rules || [];
    } else if (typeof window.CH_MOCK === "function") {
      const m = window.CH_MOCK();
      rawAlerts = m.alerts || []; rawRules = m.rules || [];
    } else {
      try {
        const [aRes, rRes] = await Promise.all([
          fetch("/api/alerts").then(r => r.json()).catch(() => ({ alerts: [] })),
          fetch("/api/rules").then(r => r.json()).catch(() => ({ rules: [] })),
        ]);
        rawAlerts = (aRes && aRes.alerts) || [];
        rawRules = (rRes && (rRes.rules || (Array.isArray(rRes) ? rRes : []))) || [];
      } catch (e) { /* leave empty */ }
    }
    const rules = normalizeRules(rawRules);
    const ruleMap = {};
    rules.forEach(r => { ruleMap[r.id] = r; });
    const alerts = normalizeAlerts(rawAlerts, ruleMap);
    return { alerts, rules };
  }

  /* ---------- live polling of /api/alerts (production) ---------- */
  async function poll(ruleMap) {
    try {
      const res = await fetch("/api/alerts").then(r => r.json());
      return normalizeAlerts((res && res.alerts) || [], ruleMap || {});
    } catch (e) { return null; }
  }

  window.CH = {
    icon, esc, sevTag, sevDot, cloudBadge, statusPill,
    SEV_STYLE, CLOUD_META, sevRank,
    fmtTime, ago, ageMinOf,
    normalizeRules, normalizeAlerts, computeStats, computeCompliance,
    makeLiveAlert, load, poll,
  };
})();
