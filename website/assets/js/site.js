// SVX site behaviour. Plain ES module; GSAP + ScrollTrigger are optional globals loaded before this file.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const html = document.documentElement;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const fine = matchMedia('(hover: hover) and (pointer: fine)').matches;
const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
const gsap = window.gsap, ST = window.ScrollTrigger;
if (gsap && ST) gsap.registerPlugin(ST);

/* theme */
function syncThemeButtons() {
  const light = html.dataset.theme === 'light';
  $$('[data-theme-toggle]').forEach(b => { b.setAttribute('aria-pressed', String(light)); b.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme'); });
}
$$('[data-theme-toggle]').forEach(b => b.addEventListener('click', () => {
  const t = html.dataset.theme === 'light' ? 'dark' : 'light';
  html.dataset.theme = t;
  try { localStorage.setItem('svx-theme', t); } catch (e) {}
  syncThemeButtons();
  dispatchEvent(new CustomEvent('svx:theme', { detail: t }));
}));
syncThemeButtons();

/* nav */
const nav = $('.nav');
if (nav) {
  let lastY = scrollY;
  const onNav = () => {
    const y = scrollY;
    nav.classList.toggle('is-scrolled', y > 8);
    if (!nav.classList.contains('is-open')) nav.classList.toggle('is-hidden', y > 400 && y > lastY + 4);
    if (y < lastY - 4) nav.classList.remove('is-hidden');
    lastY = y;
  };
  addEventListener('scroll', onNav, { passive: true }); onNav();
  nav.addEventListener('focusin', () => nav.classList.remove('is-hidden'));
  const menu = $('.nav__menu', nav);
  const close = () => { nav.classList.remove('is-open'); menu?.setAttribute('aria-expanded', 'false'); };
  menu?.addEventListener('click', () => { const o = !nav.classList.contains('is-open'); nav.classList.toggle('is-open', o); menu.setAttribute('aria-expanded', String(o)); });
  addEventListener('keydown', e => { if (e.key === 'Escape' && nav.classList.contains('is-open')) { close(); menu.focus(); } });
  $$('.nav__links a', nav).forEach(a => a.addEventListener('click', close));
}

/* headline word split */
$$('[data-split]').forEach(el => {
  let i = 0;
  const walk = node => {
    [...node.childNodes].forEach(n => {
      if (n.nodeType === 3) {
        const frag = document.createDocumentFragment();
        n.textContent.split(/(\s+)/).forEach(part => {
          if (!part) return;
          if (/^\s+$/.test(part)) { frag.append(' '); return; }
          const o = document.createElement('span'); o.className = 'split-w';
          const s = document.createElement('span'); s.textContent = part; s.style.setProperty('--i', i++);
          o.append(s); frag.append(o);
        });
        n.replaceWith(frag);
      } else if (n.nodeType === 1 && n.tagName !== 'BR') walk(n);
    });
  };
  el.setAttribute('aria-label', el.textContent.replace(/\s+/g, ' ').trim());
  walk(el);
  $$('.split-w', el).forEach(w => w.setAttribute('aria-hidden', 'true'));
});

/* reveals */
const revealEls = $$('[data-r],[data-split]');
if (reduce || !('IntersectionObserver' in window)) revealEls.forEach(el => el.classList.add('in', 'is-in'));
else {
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in', 'is-in'); io.unobserve(e.target); } }), { rootMargin: '0px 0px -8% 0px' });
  // the hero is on screen at load: reveal it straight away (its stagger comes from --d)
  revealEls.forEach(el => el.closest('.hero') ? requestAnimationFrame(() => el.classList.add('in', 'is-in')) : io.observe(el));
}

/* number counters */
$$('[data-count]').forEach(el => {
  const to = +el.dataset.count, from = +(el.dataset.from ?? 0);
  if (reduce) { el.textContent = to; return; }
  el.textContent = from;
  const run = () => {
    if (gsap) { const o = { v: from }; gsap.to(o, { v: to, duration: 1.8, ease: 'power3.out', onUpdate: () => el.textContent = Math.round(o.v) }); }
    else el.textContent = to;
  };
  const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { run(); io.disconnect(); } }, { threshold: .6 });
  io.observe(el);
});

/* scroll-filled paragraph */
$$('.fill').forEach(sec => {
  const text = $('.fill__text', sec); if (!text) return;
  const words = [];
  const walk = (node, hl) => [...node.childNodes].forEach(n => {
    if (n.nodeType === 3) {
      const frag = document.createDocumentFragment();
      n.textContent.split(/(\s+)/).forEach(p => {
        if (!p) return; if (/^\s+$/.test(p)) { frag.append(' '); return; }
        const s = document.createElement('span'); s.className = 'w' + (hl ? ' hl' : ''); s.textContent = p; words.push(s); frag.append(s);
      });
      n.replaceWith(frag);
    } else if (n.nodeType === 1) walk(n, hl || n.classList.contains('hl'));
  });
  walk(text, false);
  if (reduce) { words.forEach(w => w.classList.add('on')); return; }
  let last = -1;
  const upd = () => {
    const r = sec.getBoundingClientRect(), d = r.height - innerHeight;
    const p = d > 0 ? clamp((-r.top + innerHeight * .35) / d) : 1;
    const n = Math.floor(p * 1.1 * words.length);
    if (n === last) return; last = n;
    words.forEach((w, i) => w.classList.toggle('on', i < n));
  };
  addEventListener('scroll', upd, { passive: true }); addEventListener('resize', upd); upd();
});

/* how it works: sticky stage driven by the step in view */
$$('[data-how]').forEach(root => {
  const steps = $$('.step', root), scenes = $$('.scene', root), dots = $$('.stage__dots i', root), label = $('[data-step-label]', root);
  const set = i => {
    steps.forEach((s, k) => s.classList.toggle('on', k === i));
    scenes.forEach((s, k) => s.classList.toggle('on', k === i));
    dots.forEach((d, k) => d.classList.toggle('on', k <= i));
    if (label) label.textContent = String(i + 1).padStart(2, '0') + ' / ' + String(steps.length).padStart(2, '0');
  };
  set(0);
  if (ST && !reduce) steps.forEach((s, i) => ST.create({ trigger: s, start: 'top 60%', end: 'bottom 60%', onToggle: self => self.isActive && set(i) }));
  else {
    const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && set(steps.indexOf(e.target))), { rootMargin: '-45% 0px -45% 0px' });
    steps.forEach(s => io.observe(s));
  }
});

/* hero copy scrubs away as the 3D logo turns and the camera pulls in */
if (gsap && ST && !reduce && $('.hero__copy') && matchMedia('(min-width:901px)').matches) {
  gsap.to('.hero__copy', { yPercent: -18, opacity: 0, ease: 'none', scrollTrigger: { trigger: '.hero', start: 'top top', end: '45% top', scrub: true } });
  gsap.to('.hero__scroll', { opacity: 0, ease: 'none', scrollTrigger: { trigger: '.hero', start: 'top top', end: '10% top', scrub: true } });
}

/* lazy 3D hero */
const gl = $('.hero__gl');
if (gl && !reduce) {
  const go = () => import('./hero3d.js').then(m => m.init(gl)).catch(() => {});
  const idle = () => ('requestIdleCallback' in window ? requestIdleCallback(go, { timeout: 1500 }) : setTimeout(go, 200));
  document.readyState === 'complete' ? idle() : addEventListener('load', idle, { once: true });
}

/* card spotlight */
$$('.card').forEach(c => c.addEventListener('pointermove', e => {
  const r = c.getBoundingClientRect();
  c.style.setProperty('--mx', (e.clientX - r.left) + 'px'); c.style.setProperty('--my', (e.clientY - r.top) + 'px');
}));

/* magnetic buttons */
if (fine && !reduce) $$('[data-magnetic]').forEach(b => {
  b.addEventListener('pointermove', e => { const r = b.getBoundingClientRect(); b.style.transform = `translate(${(e.clientX - r.left - r.width / 2) * .3}px,${(e.clientY - r.top - r.height / 2) * .35}px)`; });
  b.addEventListener('pointerleave', () => { b.style.transform = ''; });
});

/* custom cursor — desktop pointers only, never with reduced motion */
if (fine && !reduce) {
  const ring = document.createElement('div'), dot = document.createElement('div');
  ring.className = 'cursor is-hidden'; dot.className = 'cursor-dot is-hidden';
  ring.setAttribute('aria-hidden', 'true'); dot.setAttribute('aria-hidden', 'true');
  document.body.append(ring, dot); html.classList.add('has-cursor');
  let x = -100, y = -100, rx = x, ry = y;
  addEventListener('pointermove', e => {
    x = e.clientX; y = e.clientY; ring.classList.remove('is-hidden'); dot.classList.remove('is-hidden');
    ring.classList.toggle('is-link', !!e.target.closest('a,button,summary,[role="tab"],label'));
  }, { passive: true });
  document.addEventListener('pointerleave', () => { ring.classList.add('is-hidden'); dot.classList.add('is-hidden'); });
  addEventListener('pointerdown', () => ring.classList.add('is-down'));
  addEventListener('pointerup', () => ring.classList.remove('is-down'));
  const tick = () => { rx += (x - rx) * .2; ry += (y - ry) * .2; ring.style.transform = `translate3d(${rx}px,${ry}px,0)`; dot.style.transform = `translate3d(${x}px,${y}px,0)`; requestAnimationFrame(tick); };
  tick();
}

/* page transitions: native cross-document view transitions where supported, fade fallback elsewhere */
if (!reduce && !('CSSViewTransitionRule' in window)) {
  document.addEventListener('click', e => {
    const a = e.target.closest('a[href]');
    if (!a || e.defaultPrevented || e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || a.target || a.hasAttribute('download')) return;
    const u = new URL(a.href, location.href);
    if (u.origin !== location.origin || (u.pathname === location.pathname && u.hash)) return;
    e.preventDefault(); document.body.classList.add('is-leaving'); setTimeout(() => { location.href = u.href; }, 220);
  });
  addEventListener('pageshow', () => document.body.classList.remove('is-leaving'));
}

/* film */
$$('.film').forEach(f => {
  const v = $('video', f), b = $('.film__play', f);
  b?.addEventListener('click', () => { f.classList.add('is-playing'); v.controls = true; v.play().catch(() => {}); v.focus(); });
});

/* learn how to use: one player, a chapter list, "Play all", subtitles */
const learn = $('[data-learn]');
if (learn) {
  const v = $('video', learn), film = $('.film', learn), items = $$('[data-ch]', learn);
  const now = $('[data-learn-now]', learn), all = $('[data-learn-all]', learn);
  const base = 'assets/media/learn/svx-learn-';
  let cur = 0, auto = false;
  const load = (i, play) => {
    cur = i;
    const id = items[i].dataset.ch;
    v.poster = `${base}${id}.jpg`;
    v.src = `${base}${id}.mp4`;
    $$('track', v).forEach(t => t.remove());
    const tr = document.createElement('track');
    Object.assign(tr, { kind: 'subtitles', srclang: 'en', label: 'English', src: `${base}${id}.vtt`, default: true });
    v.appendChild(tr);
    setTimeout(() => { if (v.textTracks[0]) v.textTracks[0].mode = 'showing'; }, 50);
    items.forEach((x, k) => { x.classList.toggle('is-current', k === i); if (k === i) x.setAttribute('aria-current', 'true'); else x.removeAttribute('aria-current'); });
    now.textContent = `${i + 1} of ${items.length} · ${items[i].dataset.title}`;
    if (play) { film.classList.add('is-playing'); v.controls = true; v.play().catch(() => {}); }
  };
  items.forEach((it, i) => it.addEventListener('click', () => { auto = false; all.setAttribute('aria-pressed', 'false'); load(i, true); }));
  all.addEventListener('click', () => { auto = true; all.setAttribute('aria-pressed', 'true'); load(0, true); });
  v.addEventListener('ended', () => { if (auto && cur < items.length - 1) load(cur + 1, true); else if (auto) { auto = false; all.setAttribute('aria-pressed', 'false'); } });
}

/* copy-to-clipboard */
$$('[data-copy]').forEach(b => b.addEventListener('click', async () => {
  const t = document.getElementById(b.dataset.copy)?.textContent.trim(); if (!t) return;
  try { await navigator.clipboard.writeText(t); b.textContent = 'Copied'; } catch (e) { b.textContent = 'Select'; }
  setTimeout(() => { b.textContent = 'Copy'; }, 1600);
}));

/* download page: when the file download starts, say how to avoid the macOS warning */
const dlNotice = document.getElementById('dl-notice');
if (dlNotice) {
  const close = () => { dlNotice.hidden = true; };
  $$('a[download][href$=".dmg"]').forEach(a => a.addEventListener('click', () => { dlNotice.hidden = false; dlNotice.focus(); }));
  $('.dl-notice__close', dlNotice)?.addEventListener('click', close);
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !dlNotice.hidden) close(); });
}

/* OS detection (download page) + tabs */
const ua = navigator.userAgent, plat = (navigator.userAgentData?.platform || navigator.platform || '').toLowerCase();
const os = /mac/.test(plat) || /Mac OS X/.test(ua) ? 'mac' : /win/.test(plat) || /Windows/.test(ua) ? 'win' : /linux/.test(plat) || /Linux/.test(ua) ? 'linux' : '';
if (os && !/Android|iPhone|iPad/.test(ua)) $$(`[data-os="${os}"]`).forEach(el => el.classList.add('is-yours'));
$$('[role="tablist"]').forEach(list => {
  const tabs = $$('[role="tab"]', list);
  const pick = (t, focus) => { tabs.forEach(x => { const on = x === t; x.setAttribute('aria-selected', String(on)); x.tabIndex = on ? 0 : -1; document.getElementById(x.getAttribute('aria-controls')).hidden = !on; }); if (focus) t.focus(); };
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => pick(t));
    t.addEventListener('keydown', e => { const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0; if (d) { e.preventDefault(); pick(tabs[(i + d + tabs.length) % tabs.length], true); } });
  });
  const pre = os && tabs.find(t => t.dataset.tab === os); pick(pre || tabs[0]);
});

/* docs table of contents */
const toc = $$('.toc a[href^="#"]');
if (toc.length) {
  const map = new Map(toc.map(a => [a.getAttribute('href').slice(1), a]));
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { toc.forEach(a => a.classList.remove('on')); map.get(e.target.id)?.classList.add('on'); } }), { rootMargin: '-20% 0px -70% 0px' });
  map.forEach((a, id) => { const s = document.getElementById(id); s && io.observe(s); });
}

$$('[data-year]').forEach(el => { el.textContent = new Date().getFullYear(); });
