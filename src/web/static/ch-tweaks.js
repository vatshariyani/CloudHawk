/* ============================================================
   CloudHawk Console — Tweaks panel (#2 refine the design)
   Accent · Nav layout · Density. Persists to localStorage and
   applies to <body> data attributes (see cloudhawk.css).
   Mounts only when <body data-tweaks="on">.
   ============================================================ */
(function () {
  "use strict";
  const KEY = "cloudhawk.tweaks";
  const DEF = { accent: "amber", nav: "side", density: "comfortable" };
  const ACCENTS = [
    { id: "amber", color: "#e8912d" },
    { id: "blue", color: "#4f8ff7" },
    { id: "green", color: "#3fbf86" },
    { id: "violet", color: "#9b7bf0" },
  ];

  function load() {
    try { return Object.assign({}, DEF, JSON.parse(localStorage.getItem(KEY) || "{}")); }
    catch (e) { return Object.assign({}, DEF); }
  }
  function save(t) { try { localStorage.setItem(KEY, JSON.stringify(t)); } catch (e) {} }

  function apply(t) {
    const b = document.body;
    b.dataset.accent = t.accent === "amber" ? "" : t.accent; // amber is the :root default
    if (t.accent === "amber") b.removeAttribute("data-accent");
    b.dataset.nav = t.nav === "side" ? "" : t.nav;
    if (t.nav === "side") b.removeAttribute("data-nav");
    b.dataset.density = t.density === "comfortable" ? "" : t.density;
    if (t.density === "comfortable") b.removeAttribute("data-density");
  }

  function mount() {
    if (document.body.dataset.tweaks !== "on") return;
    const t = load();
    apply(t);

    const fab = document.createElement("button");
    fab.className = "tw-fab";
    fab.title = "Tweaks";
    fab.innerHTML = CH.icon("sliders", { size: 20 });
    document.body.appendChild(fab);

    let panel = null;
    function close() { if (panel) { panel.remove(); panel = null; } }
    function open() {
      panel = document.createElement("div");
      panel.className = "tw-panel";
      panel.innerHTML =
        '<div class="tw-head"><span class="tw-head-title">Tweaks</span>' +
          '<button class="icon-btn" data-tw="close" style="width:28px;height:28px">' + CH.icon("x", { size: 15 }) + '</button></div>' +
        '<div class="tw-body">' +
          '<div><div class="tw-group-label">Accent</div><div class="tw-swatches">' +
            ACCENTS.map(a => '<button class="tw-swatch' + (t.accent === a.id ? " on" : "") + '" data-accent="' + a.id + '" style="background:' + a.color + '"></button>').join("") +
          '</div></div>' +
          '<div><div class="tw-group-label">Navigation</div><div class="tw-seg" data-tw-seg="nav">' +
            '<button data-val="side" class="' + (t.nav === "side" ? "on" : "") + '">Sidebar</button>' +
            '<button data-val="top" class="' + (t.nav === "top" ? "on" : "") + '">Top bar</button></div></div>' +
          '<div><div class="tw-group-label">Density</div><div class="tw-seg" data-tw-seg="density">' +
            '<button data-val="comfortable" class="' + (t.density === "comfortable" ? "on" : "") + '">Comfortable</button>' +
            '<button data-val="compact" class="' + (t.density === "compact" ? "on" : "") + '">Compact</button></div></div>' +
        '</div>';
      document.body.appendChild(panel);
      panel.querySelector('[data-tw="close"]').onclick = close;
      panel.querySelectorAll("[data-accent]").forEach(b => b.onclick = () => {
        t.accent = b.dataset.accent; save(t); apply(t);
        panel.querySelectorAll("[data-accent]").forEach(x => x.classList.toggle("on", x === b));
      });
      panel.querySelectorAll("[data-tw-seg]").forEach(seg => {
        const key = seg.dataset.twSeg;
        seg.querySelectorAll("button").forEach(b => b.onclick = () => {
          t[key] = b.dataset.val; save(t); apply(t);
          seg.querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
        });
      });
    }
    fab.onclick = () => panel ? close() : open();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
  window.CH_TWEAKS = { apply, load };
})();
