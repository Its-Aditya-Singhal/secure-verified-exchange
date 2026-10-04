// The protected viewer window (Phase 7). It receives rendered pages as raw
// pixels with the watermark already burned in, and draws them on canvases.
// It never gets the document, its text or its bytes, so there is nothing to
// copy, save or print; the window itself is hidden from screenshots and
// recordings by the OS (set in Rust). The handlers below are only friction:
// the protection is that nothing but pictures ever arrives here.

import "./style.css";
import { type ShareStatus, type ViewInfo, api, asAppError } from "./api";
import { errorPanel, note } from "./components";
import { button, clear, fmtTime, h, revealLabel } from "./dom";

const root = document.getElementById("viewer")!;
const id = Number(new URLSearchParams(location.search).get("id"));

// ----- No copy, save, print, drag or context menu -----

for (const ev of ["contextmenu", "copy", "cut", "dragstart", "dragover", "drop", "selectstart"]) {
  document.addEventListener(ev, (e) => e.preventDefault());
}
document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && ["a", "c", "p", "s", "x", "u", "o"].includes(e.key.toLowerCase())) e.preventDefault();
  if (e.key === "PrintScreen") e.preventDefault();
});

// ----- Layout -----

const ZOOMS = [0.5, 0.75, 1, 1.25, 1.5, 2, 3];
let zoom = 2; // index into ZOOMS: 100%
let info: ViewInfo | null = null;

const pagesEl = h("div", { class: "view-pages", tabindex: "0" });
const pageLabel = h("span", { class: "view-page-label" }, "");
const zoomLabel = h("span", { class: "view-zoom-label" }, "100%");
const shareSlot = h("div", { class: "view-share" });
const message = h("div", { class: "view-message" });

interface PageView {
  wrap: HTMLElement;
  canvas: HTMLCanvasElement;
  /** What is drawn now ("zoom:width"), to skip redundant renders. */
  drawn: string | null;
  gen: number;
  visible: boolean;
}
let pages: PageView[] = [];

/** CSS width of a page at the current zoom. */
function cssWidth(): number {
  const room = Math.max(240, pagesEl.clientWidth - 40);
  return Math.round(Math.min(room, 1100) * ZOOMS[zoom]);
}

function layout() {
  if (!info) return;
  const w = cssWidth();
  info.pages.forEach(([pw, ph], i) => {
    pages[i].wrap.style.width = `${w}px`;
    pages[i].wrap.style.height = `${Math.round((w * ph) / Math.max(1, pw))}px`;
  });
  zoomLabel.textContent = `${Math.round(ZOOMS[zoom] * 100)}%`;
  for (const p of pages) if (p.visible) void draw(pages.indexOf(p));
}

async function draw(i: number) {
  const p = pages[i];
  const w = cssWidth();
  const px = Math.round(w * (window.devicePixelRatio || 1));
  const key = `${zoom}:${px}`;
  if (p.drawn === key) return;
  const gen = ++p.gen;
  try {
    const buf = await api.viewPage(id, i, px);
    if (gen !== p.gen || !p.visible) return;
    const dv = new DataView(buf);
    const iw = dv.getUint32(0, true);
    const ih = dv.getUint32(4, true);
    const ctx = p.canvas.getContext("2d");
    if (!ctx || buf.byteLength !== 8 + iw * ih * 4) throw new Error("unexpected page data");
    p.canvas.width = iw;
    p.canvas.height = ih;
    ctx.putImageData(new ImageData(new Uint8ClampedArray(buf, 8), iw, ih), 0, 0);
    p.drawn = key;
  } catch (e) {
    if (gen !== p.gen) return;
    clear(message);
    message.appendChild(errorPanel(asAppError(e)));
  }
}

/** Free pages that scrolled far away; draw the ones coming into view. */
const observer = new IntersectionObserver(
  (entries) => {
    for (const en of entries) {
      const i = pages.findIndex((p) => p.wrap === en.target);
      if (i < 0) continue;
      pages[i].visible = en.isIntersecting;
      if (en.isIntersecting) {
        void draw(i);
      } else {
        pages[i].gen++;
        pages[i].canvas.width = 0;
        pages[i].canvas.height = 0;
        pages[i].drawn = null;
      }
    }
  },
  { root: pagesEl, rootMargin: "900px 0px" },
);

function currentPage(): number {
  const top = pagesEl.getBoundingClientRect().top + 60;
  const i = pages.findIndex((p) => p.wrap.getBoundingClientRect().bottom > top);
  return i < 0 ? pages.length - 1 : i;
}

function goTo(i: number) {
  const n = Math.max(0, Math.min(pages.length - 1, i));
  pages[n]?.wrap.scrollIntoView({ block: "start" });
}

function updateLabel() {
  if (info) pageLabel.textContent = `Page ${currentPage() + 1} of ${pages.length}`;
}

let scrollQueued = false;
pagesEl.addEventListener("scroll", () => {
  if (scrollQueued) return;
  scrollQueued = true;
  requestAnimationFrame(() => {
    scrollQueued = false;
    updateLabel();
  });
});

let resizeTimer = 0;
window.addEventListener("resize", () => {
  window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(layout, 150);
});

function setZoom(z: number) {
  const keep = currentPage();
  zoom = Math.max(0, Math.min(ZOOMS.length - 1, z));
  layout();
  goTo(keep);
  updateLabel();
}

document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === "+" || e.key === "=") setZoom(zoom + 1);
  else if (e.key === "-") setZoom(zoom - 1);
  else if (e.key === "0") setZoom(2);
  else if (e.key === "PageDown" || e.key === "ArrowRight") goTo(currentPage() + 1);
  else if (e.key === "PageUp" || e.key === "ArrowLeft") goTo(currentPage() - 1);
  else if (e.key === "Home") goTo(0);
  else if (e.key === "End") goTo(pages.length - 1);
  else if (e.key === "Escape") void api.viewClose();
});

// ----- Keep a copy -----

let poll = 0;

function renderShare(s: ShareStatus) {
  clear(shareSlot);
  window.clearInterval(poll);
  switch (s.state) {
    case "not_requested":
      shareSlot.appendChild(button("Ask to keep a copy", () => void ask(), "secondary"));
      break;
    case "pending":
      shareSlot.append(h("span", { class: "muted small" }, "Waiting for the sender to answer…"));
      poll = window.setInterval(() => void refreshShare(), 5000);
      break;
    case "approved":
    case "unrestricted":
      shareSlot.appendChild(button("Save a copy", () => void save(), "primary"));
      break;
    case "declined":
      shareSlot.append(h("span", { class: "muted small" }, "The sender declined to let you keep a copy."));
      break;
    case "forbidden":
      shareSlot.append(h("span", { class: "muted small" }, "The sender doesn't allow copies."));
      break;
  }
}

async function refreshShare() {
  try {
    renderShare(await api.viewShare(id, false));
  } catch {
    // Offline or the service is busy: the button stays as it was.
  }
}

async function ask() {
  clear(message);
  try {
    renderShare(await api.viewShare(id, true));
  } catch (e) {
    message.appendChild(errorPanel(asAppError(e)));
  }
}

async function save() {
  clear(message);
  try {
    const r = await api.viewSave(id);
    message.appendChild(
      h("div", { class: "panel panel-ok", role: "status" },
        h("p", {}, `Saved ${r.name} to `, h("span", { class: "mono" }, r.path), "."),
        h("div", { class: "actions" }, button(revealLabel(), () => void api.reveal(r.path), "primary"))));
  } catch (e) {
    const x = asAppError(e);
    if (x.kind === "denied" && x.deny_reason === "already_opened") {
      message.appendChild(note(
        "This was a one-time file and you've already viewed it, so it can't be saved now. " +
          "Ask the sender to send it again with one-time turned off.", "warn"));
    } else {
      message.appendChild(errorPanel(x));
    }
  }
}

// ----- Start -----

async function start() {
  try {
    info = await api.viewInfo(id);
  } catch (e) {
    root.appendChild(errorPanel(asAppError(e)));
    return;
  }
  document.title = `${info.file_name} (view only)`;
  const bar = h("header", { class: "view-bar" },
    h("div", { class: "view-title" },
      h("strong", {}, info.file_name),
      h("span", { class: "badge badge-warn" }, "View only"),
      h("span", { class: "muted small" }, `from ${info.sender}`)),
    h("div", { class: "view-tools" },
      button("‹", () => goTo(currentPage() - 1), "link"), pageLabel, button("›", () => goTo(currentPage() + 1), "link"),
      button("−", () => setZoom(zoom - 1), "link"), zoomLabel, button("+", () => setZoom(zoom + 1), "link")),
    shareSlot,
    button("Close", () => void api.viewClose()));
  root.append(bar, message, pagesEl);
  pages = info.pages.map(() => {
    const canvas = h("canvas", { class: "view-canvas" });
    const wrap = h("div", { class: "view-page" }, canvas);
    pagesEl.appendChild(wrap);
    observer.observe(wrap);
    return { wrap, canvas, drawn: null, gen: 0, visible: false };
  });
  layout();
  updateLabel();
  pagesEl.focus();
  void refreshShare();
  // Not shown here, but the sender knows: a note about what this view is.
  root.appendChild(h("footer", { class: "view-foot muted small" },
    `Opened ${fmtTime(Math.floor(Date.now() / 1000))}. Each page carries your email and the time. Closing this window ends the view.`));
}

void start();
