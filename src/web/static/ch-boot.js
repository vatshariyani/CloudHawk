/* ============================================================
   CloudHawk Console — boot / routing / live engine
   Works in two modes:
     • Production : one Flask route per page; #screen-root[data-screen]
                    is rendered once; live data via polling /api/alerts.
     • Preview    : window.__CH_PREVIEW set; hash router drives all screens
                    and the live stream is synthesised.
   ============================================================ */
(function () {
  "use strict";

  function $(s, r) { return (r || document).querySelector(s); }
  function $$(s, r) { return [...(r || document).querySelectorAll(s)]; }

  function setActiveNav(screen) {
    $$(".nav-item[data-screen]").forEach(n => n.classList.toggle("active", n.dataset.screen === screen));
  }

  function refreshNav() {
    const stats = CH.computeStats(APP.alerts);
    // sidebar critical badge on the Alerts nav item
    $$('.nav-item[data-screen="alerts"]').forEach(item => {
      let badge = item.querySelector(".nav-badge");
      const collapsed = document.querySelector(".sidebar.collapsed");
      if (stats.bySeverity.CRITICAL > 0) {
        if (!badge) { badge = document.createElement("span"); badge.className = "nav-badge"; item.appendChild(badge); }
        badge.className = "nav-badge" + (collapsed ? " dot" : "");
        badge.textContent = collapsed ? "" : stats.bySeverity.CRITICAL;
      } else if (badge) { badge.remove(); }
    });
    // topbar crit / high counters
    const tc = $("#tb-crit"), th = $("#tb-high");
    if (tc) tc.textContent = stats.bySeverity.CRITICAL;
    if (th) th.textContent = stats.bySeverity.HIGH;
  }

  function renderScreen(screen) {
    const root = $("#screen-root");
    if (!root) return;
    const fn = (window.SCREENS && window.SCREENS[screen]) || (window.PREVIEW_SCREENS && window.PREVIEW_SCREENS[screen]);
    root.dataset.active = screen;
    if (fn) fn(root);
    setActiveNav(screen);
    refreshNav();
  }

  /* ---------- chrome wiring (sidebar / topbar) ---------- */
  function wireChrome() {
    // collapse
    const cb = $("[data-act='collapse']");
    if (cb) cb.onclick = () => {
      const sb = $(".sidebar"); const app = $(".app");
      const collapsed = sb.classList.toggle("collapsed");
      if (app) app.classList.toggle("nav-collapsed", collapsed);
      try { localStorage.setItem("cloudhawk.collapsed", collapsed ? "1" : "0"); } catch (e) {}
      refreshNav();
    };
    try {
      if (localStorage.getItem("cloudhawk.collapsed") === "1") {
        const sb = $(".sidebar"), app = $(".app");
        if (sb) sb.classList.add("collapsed"); if (app) app.classList.add("nav-collapsed");
      }
    } catch (e) {}

    // mobile menu
    const mb = $("[data-act='menu']");
    if (mb) mb.onclick = () => { const sb = $(".sidebar"); if (sb) sb.classList.toggle("mobile-open"); };

    // topbar live toggle
    const lt = $("[data-act='topbar-live']");
    if (lt) lt.onclick = () => { APP.live = !APP.live; paintLive(); };

    // topbar search → alerts with query
    const ts = $("#tb-search");
    if (ts) ts.addEventListener("keydown", e => {
      if (e.key === "Enter" && ts.value.trim()) {
        if (window.__CH_PREVIEW) { window.aSetQuery && window.aSetQuery(ts.value.trim()); location.hash = "#alerts"; }
        else location.href = "/alerts?q=" + encodeURIComponent(ts.value.trim());
      }
    });
    document.addEventListener("keydown", e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); if (ts) ts.focus(); }
    });
  }

  function paintLive() {
    $$(".live-dot").forEach(d => d.classList.toggle("on", APP.live));
    const chip = $("[data-act='topbar-live']");
    if (chip) { chip.classList.toggle("active", APP.live); chip.innerHTML = CH.icon(APP.live ? "pulse" : "refresh", { size: 14 }) + (APP.live ? "Live" : "Paused"); }
    APP.refreshActive && APP.refreshActive();
  }

  /* ---------- live engine ---------- */
  let liveTimer = null;
  function startLive() {
    function loop() {
      const delay = window.__CH_PREVIEW ? (4200 + Math.random() * 4200) : 20000;
      liveTimer = setTimeout(async () => {
        if (APP.live) {
          if (window.__CH_PREVIEW) {
            const na = CH.makeLiveAlert(APP.alerts);
            if (na) {
              APP.alerts = [na, ...APP.alerts].slice(0, 600);
              setTimeout(() => { APP.alerts = APP.alerts.map(a => a.id === na.id ? Object.assign({}, a, { _new: false }) : a); }, 2400);
              tickActive();
            }
          } else {
            const fresh = await CH.poll(APP.ruleMap);
            if (fresh) { APP.alerts = fresh; tickActive(); }
          }
        }
        loop();
      }, delay);
    }
    loop();
  }
  function tickActive() {
    refreshNav();
    const root = $("#screen-root");
    if (!root) return;
    const s = root.dataset.active;
    if (s === "overview") window.SCREENS.overview(root);
    else if (s === "timeline" && window.SCREENS.timeline) renderScreen("timeline");
    // alerts/rules: leave selection intact, do not auto-clobber while user works
  }

  /* ---------- deep link (?alert=ID) ---------- */
  function openDeepLink() {
    const params = new URLSearchParams(location.search);
    const id = params.get("alert");
    if (id) setTimeout(() => APP.openDrawer && APP.openDrawer(id), 60);
    const q = params.get("q");
    if (q) { const box = $("#a-q"); if (box) { box.value = q; box.dispatchEvent(new Event("input")); } }
  }

  /* ---------- preview hash router ---------- */
  function startRouter() {
    function go() {
      const screen = (location.hash.slice(1) || "overview").split("?")[0];
      renderScreen(screen);
    }
    window.addEventListener("hashchange", go);
    $$(".nav-item[data-screen]").forEach(n => { if (!n.getAttribute("href")) n.onclick = () => { location.hash = "#" + n.dataset.screen; }; });
    go();
    startLive();
  }

  /* ---------- go ---------- */
  async function boot() {
    const data = await CH.load();
    APP.alerts = data.alerts; APP.rules = data.rules;
    APP.ruleMap = {}; APP.rules.forEach(r => { APP.ruleMap[r.id] = r; });
    APP.onChange = refreshNav;
    wireChrome();
    paintLive();

    if (window.__CH_PREVIEW) {
      startRouter();
    } else {
      const root = $("#screen-root");
      if (root && root.dataset.screen) {
        renderScreen(root.dataset.screen);
        openDeepLink();
        startLive();
      } else {
        // pages without a JS screen (scan/config) still get nav + live counters
        setActiveNav(document.body.dataset.screen || "");
        refreshNav();
      }
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
