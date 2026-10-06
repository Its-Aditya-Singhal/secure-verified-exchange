// Presentation only: every check and change is made by svx-admin on the server.
'use strict';

const $ = (id) => document.getElementById(id);
let current = null;
let ended = false;

async function api(path, body) {
  const opts = body === undefined
    ? { headers: { 'X-SVX-Admin': '1' } }
    : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SVX-Admin': '1' }, body: JSON.stringify(body) };
  let resp;
  try {
    resp = await fetch(path, opts);
  } catch {
    sessionEnded('The admin session has ended (the Terminal window was closed or it was idle for 30 minutes). Run scripts/admin.sh again.');
    throw new Error('offline');
  }
  const data = await resp.json().catch(() => ({}));
  if (resp.status === 401) {
    sessionEnded(data.error || 'This admin session has ended. Run scripts/admin.sh again.');
    throw new Error('ended');
  }
  if (!resp.ok) throw new Error(data.error || `error ${resp.status}`);
  return data;
}

function sessionEnded(text) {
  if (ended) return;
  ended = true;
  show($('banner'), text, true);
  if ($('detail').open) $('detail').close();
}

function show(el, text, error) {
  el.textContent = text;
  el.classList.toggle('error', !!error);
  el.hidden = !text;
}

function day(t) {
  if (t === null || t === undefined) return '–';
  return new Date(t * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const KINDS = [
  ['code', 'sign-in, sign-up and password-reset codes'],
  ['notice', 'approval and copy requests'],
  ['admin', 'suspended, restored or deleted notices'],
  ['announcement', 'announcements'],
  ['test', 'test announcements'],
  ['alert', 'server health alerts'],
  ['welcome', 'welcome emails'],
];

/** "12 sign-in… codes · 3 approval…", only kinds sent in the last 24 h. */
function breakdown(u) {
  const parts = KINDS.filter(([k]) => u.by_kind[k]).map(([k, label]) => `${u.by_kind[k]} ${label}`);
  return parts.length ? parts.join(' · ') : 'none yet';
}

async function loadStats() {
  const [s, u] = await Promise.all([api('/api/stats'), api('/api/email-usage')]);
  const cards = [
    ['Accounts', s.accounts, `${s.accounts_7d} new this week · ${s.accounts_30d} this month`],
    ['Sign-in', `${s.email_accounts} / ${s.google_accounts}`, 'email / Google'],
    ['Suspended', s.suspended, ''],
    ['Files sent', s.files, `${s.files_7d} this week`],
    ['Opens', s.opens_7d, 'in the last 7 days'],
    ['Waiting for approval', s.pending_approvals, ''],
    ['Database', `${(s.database_bytes / 1e6).toFixed(1)} MB`, ''],
    ['Emails, last 24 hours', `${u.used} / ${u.limit}`, `${u.limit - u.used} left in Gmail's daily limit`],
  ];
  const box = $('stats');
  const mailNote = el('p', 'muted small mail-note', `Emails in the last 24 hours: ${breakdown(u)}.`);
  box.replaceChildren(...cards.map(([k, v, sub]) => {
    const c = el('div', 'card');
    c.append(el('div', 'v', String(v)), el('div', 'k', k));
    if (sub) c.append(el('div', 's', sub));
    return c;
  }), mailNote);
}

function status(u) {
  return u.suspended_at ? el('span', 'pill off', 'suspended') : el('span', 'pill ok', 'active');
}

async function loadUsers() {
  const q = $('search').value.trim();
  const list = await api('/api/users?limit=500' + (q ? '&search=' + encodeURIComponent(q) : ''));
  const body = $('users');
  if (!list.length) {
    const tr = el('tr');
    const td = el('td', 'empty', q ? 'No account matches.' : 'No accounts yet.');
    td.colSpan = 6;
    tr.append(td);
    body.replaceChildren(tr);
  } else {
    body.replaceChildren(...list.map((u) => {
      const tr = el('tr');
      tr.tabIndex = 0;
      const st = el('td');
      st.append(status(u));
      tr.append(el('td', '', u.email), el('td', '', u.name || '–'), el('td', '', u.sign_in),
        el('td', '', day(u.created_at)), el('td', '', day(u.last_active)), st);
      tr.addEventListener('click', () => openDetail(u.account));
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') openDetail(u.account); });
      return tr;
    }));
  }
  $('count').textContent = `${list.length} shown`;
}

async function refresh() {
  if (ended) return;
  try {
    await Promise.all([loadStats(), loadUsers()]);
    if (!ended) show($('banner'), '');
  } catch (e) {
    if (!ended) show($('banner'), e.message, true);
  }
}

async function openDetail(account, keepMessage) {
  if (!keepMessage) show($('d-msg'), '');
  $('d-reason').value = '';
  $('d-del-reason').value = '';
  $('d-confirm').value = '';
  $('d-delete-btn').disabled = true;
  try {
    const d = await api('/api/user/' + encodeURIComponent(account));
    current = d.user;
    $('d-email').textContent = d.user.email;
    $('d-name').textContent = d.user.name || 'No name given';
    const a = d.activity;
    const facts = [
      ['Account ID', d.user.account],
      ['Sign-in', d.user.sign_in],
      ['Created', day(d.user.created_at)],
      ['Last active', day(d.user.last_active)],
      ['Status', d.user.suspended_at
        ? `Suspended ${day(d.user.suspended_at)}${d.user.suspended_reason ? ' — ' + d.user.suspended_reason : ''}`
        : 'Active'],
      ['Files sent', a.files_sent],
      ['Files received', a.files_received],
      ['Opens', a.opens],
      ['Waiting for their approval', a.pending_approvals],
      ['Active keys', a.active_keys],
    ];
    $('d-facts').replaceChildren(...facts.flatMap(([k, v]) => [el('dt', '', k), el('dd', '', String(v))]));
    $('d-annoff').checked = !!d.user.announcements_off;
    $('d-suspend').hidden = !!d.user.suspended_at;
    $('d-unsuspend').hidden = !d.user.suspended_at;
    if (!$('detail').open) $('detail').showModal();
  } catch (e) {
    if (!ended) show($('banner'), e.message, true);
  }
}

async function act(path, body, button) {
  button.disabled = true;
  try {
    const r = await api(path, body);
    show($('d-msg'), r.message);
    await refresh();
    return true;
  } catch (e) {
    if (!ended) show($('d-msg'), e.message, true);
    return false;
  } finally {
    button.disabled = false;
  }
}


// ---- Tabs ----
let tab = 'accounts';
function showTab(name) {
  tab = name;
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('is-on', b.dataset.tab === name);
  for (const t of ['accounts', 'logs', 'announce']) $('tab-' + t).hidden = t !== name;
  if (name === 'logs') loadLogs().catch(fail);
  if (name === 'announce') loadAnnounce().catch(fail);
}
function fail(e) { if (!ended) show($('banner'), e.message, true); }

function when(t) {
  return new Date(t * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ---- Logs ----
const EVENTS = {
  artifact_registered: 'sent a file',
  artifact_shared: 'shared a file',
  artifact_revoked: 'revoked a file',
  decryption_authorized: 'opened a file',
  approval_requested: 'asked to open a file',
  approval_granted: 'approved a request',
  approval_declined: 'declined a request',
  share_requested: 'asked to keep a copy',
  share_granted: 'allowed a copy',
  share_declined: 'refused a copy',
  authentication_failure: 'sign-in or signature refused',
  authorization_failure: 'not allowed to open',
  signature_failure: 'bad signature',
  artifact_expired: 'tried an expired file',
  revoked_artifact_access: 'tried a revoked file',
  replay_detected: 'replayed request blocked',
  key_release_failure: 'key release failed',
  suspicious_repeated_attempts: 'many failed attempts',
  key_changed: 'keys changed',
  password_changed: 'password changed',
  account_suspended: 'account suspended',
  account_unsuspended: 'suspension lifted',
  org_registered: 'organization registered',
  org_verified: 'organization verified',
  admin_added: 'administrator added',
  admin_removed: 'administrator removed',
  org_changed: 'organization changed',
  policy_changed: 'policy changed',
  admin_authentication_failure: 'admin sign-in refused',
  // What you did (admin page and svx-admin).
  suspended: 'you suspended the account',
  unsuspended: 'you lifted the suspension',
  erased: 'you deleted the account',
  announcements_off: 'you turned announcements off',
  announcements_on: 'you turned announcements on',
  announcement: 'you sent an announcement',
  announcement_test: 'you sent a test announcement',
  announcement_stopped: 'you stopped an announcement',
};
const PROBLEMS = new Set(['authentication_failure', 'authorization_failure', 'signature_failure', 'artifact_expired',
  'revoked_artifact_access', 'replay_detected', 'key_release_failure', 'suspicious_repeated_attempts',
  'admin_authentication_failure', 'approval_declined', 'share_declined', 'account_suspended']);
let logPage = 0;

function fillEventFilter() {
  const sel = $('log-event');
  const opts = [['', 'All events'], ...Object.entries(EVENTS)];
  sel.replaceChildren(...opts.map(([v, label]) => { const o = el('option', '', label); o.value = v; return o; }));
}

async function loadLogs() {
  const p = new URLSearchParams({ page: String(logPage) });
  const q = $('log-search').value.trim();
  if (q) p.set('search', q);
  if ($('log-event').value) p.set('event', $('log-event').value);
  if ($('log-problems').checked) p.set('problems', 'true');
  const r = await api('/api/logs?' + p);
  const body = $('logs');
  if (!r.entries.length) {
    const tr = el('tr'); const td = el('td', 'empty', 'Nothing here.'); td.colSpan = 6; tr.append(td);
    body.replaceChildren(tr);
  } else {
    body.replaceChildren(...r.entries.map((e) => {
      const tr = el('tr');
      const cls = e.source === 'admin' ? 'ev-admin' : PROBLEMS.has(e.event) ? 'ev-problem' : '';
      const who = e.email || (e.account ? (e.source === 'admin' ? e.account : 'deleted account') : '–');
      tr.append(el('td', '', when(e.at)), el('td', '', who), el('td', cls, EVENTS[e.event] || e.event),
        el('td', '', e.subject || ''), el('td', 'mono', e.artifact_id ? e.artifact_id.slice(0, 12) : ''),
        el('td', 'wrap', e.reason || ''));
      return tr;
    }));
  }
  $('log-newer').disabled = logPage === 0;
  $('log-older').disabled = !r.more;
  $('log-page').textContent = `Page ${logPage + 1}`;
}

// ---- Announcements ----
let people = [];
const picked = new Set();
let files = [];
let usage = null;
const eligible = (u) => !u.suspended_at && !u.announcements_off;

async function loadAnnounce() {
  const [u, list, hist] = await Promise.all([api('/api/email-usage'), api('/api/users?limit=10000'), api('/api/announcements')]);
  usage = u;
  people = list;
  for (const id of [...picked]) if (!people.some((p) => p.account === id && eligible(p))) picked.delete(id);
  drawUsage();
  drawPeople();
  drawHistory(hist);
}

function drawUsage() {
  const u = usage;
  const box = $('usage');
  const meter = el('div', 'meter');
  const other = el('span', 'm-other'); other.style.width = `${Math.min(100, ((u.used - u.announcements) / u.limit) * 100)}%`;
  const ann = el('span', 'm-ann'); ann.style.width = `${Math.min(100, (u.announcements / u.limit) * 100)}%`;
  meter.append(other, ann);
  box.replaceChildren(
    el('strong', '', `Emails in the last 24 hours: ${u.used} / ${u.limit} (${u.limit - u.used} left)`),
    el('div', 'muted small', `Every email SVX sent: ${breakdown(u)}.`),
    meter,
    el('div', 'muted small', `Announcements stop at ${u.announce_ceiling}, so new users always get their codes: ${u.announce_room} more announcement emails can go out now. Emails you send yourself from the Gmail account also count towards Gmail's limit but aren't shown here.`),
  );
}

function drawPeople() {
  const q = $('r-search').value.trim().toLowerCase();
  const shown = people.filter((p) => !q || p.email.toLowerCase().includes(q) || (p.name || '').toLowerCase().includes(q));
  const body = $('recipients');
  body.replaceChildren(...shown.map((p) => {
    const ok = eligible(p);
    const tr = el('tr', ok ? '' : 'off');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.disabled = !ok;
    box.checked = picked.has(p.account);
    box.setAttribute('aria-label', p.email);
    box.addEventListener('change', () => { if (box.checked) picked.add(p.account); else picked.delete(p.account); drawPlan(); });
    const c = el('td'); c.append(box);
    tr.append(c, el('td', '', p.email), el('td', '', p.name || '–'),
      el('td', 'muted', p.suspended_at ? 'suspended' : p.announcements_off ? 'unsubscribed' : ''));
    return tr;
  }));
  const n = people.filter(eligible).length;
  $('r-all').textContent = `Select all (${n})`;
  drawPlan();
}

function drawPlan() {
  const n = picked.size;
  $('r-count').textContent = `${n} selected of ${people.filter(eligible).length} who can get announcements`;
  const room = usage ? usage.announce_room : 0;
  let text;
  if (!n) text = 'Choose who gets it.';
  else if (n <= room) text = `All ${n} can be sent now.`;
  else if ($('a-queue').checked) text = `${room} go out now; the other ${n - room} wait and go out over the next days.`;
  else text = `Only ${room} can go out today. Tick "queue the rest" to send the other ${n - room} over the next days, or they won't be sent.`;
  $('a-plan').textContent = text;
  $('a-send').disabled = !n;
  $('a-send').textContent = n ? `Send to ${n}` : 'Send';
}

function drawFiles() {
  const total = files.reduce((s, f) => s + f.size, 0);
  $('a-filelist').replaceChildren(...files.map((f, i) => {
    const li = el('li');
    const rm = el('button', 'ghost', 'Remove');
    rm.type = 'button';
    rm.addEventListener('click', () => { files.splice(i, 1); drawFiles(); });
    li.append(el('span', '', f.name), el('span', 'muted small', `${(f.size / 1e6).toFixed(2)} MB`), rm);
    return li;
  }), ...(files.length ? [el('li', 'muted small', `${files.length} file(s), ${(total / 1e6).toFixed(2)} MB of 10 MB`)] : []));
}

function readBase64(file) {
  return new Promise((ok, no) => {
    const r = new FileReader();
    r.onload = () => ok(String(r.result).split(',', 2)[1] || '');
    r.onerror = () => no(new Error(`couldn't read ${file.name}`));
    r.readAsDataURL(file);
  });
}

async function draft() {
  const out = { subject: $('a-subject').value, body: $('a-body').value, files: [] };
  for (const f of files) out.files.push({ name: f.name, content_type: f.type || 'application/octet-stream', data: await readBase64(f) });
  return out;
}

async function sendTest(btn) {
  btn.disabled = true;
  try {
    const r = await api('/api/announcements/test', { ...(await draft()), to: $('a-test-to').value });
    show($('a-msg'), r.message);
    await loadAnnounce();
  } catch (e) { if (!ended) show($('a-msg'), e.message, true); }
  finally { btn.disabled = false; }
}

async function sendAll(btn) {
  const n = picked.size;
  const subject = $('a-subject').value.trim() || '(no subject)';
  if (!window.confirm(`Send "${subject}" to ${n} ${n === 1 ? 'person' : 'people'}? This can't be undone, but you can stop the ones still waiting.`)) return;
  btn.disabled = true;
  try {
    const r = await api('/api/announcements', { ...(await draft()), accounts: [...picked], queue_rest: $('a-queue').checked });
    let m = `Announcement saved: ${r.recipients} will get it (${r.today} today).`;
    if (r.left_out) m += ` ${r.left_out} left out: no room today.`;
    if (r.skipped) m += ` ${r.skipped} skipped: suspended or unsubscribed.`;
    m += ' The service sends them in the background, a few every 15 seconds.';
    show($('a-msg'), m);
    $('a-subject').value = ''; $('a-body').value = ''; files = []; drawFiles(); picked.clear();
    await loadAnnounce();
  } catch (e) { if (!ended) show($('a-msg'), e.message, true); }
  finally { btn.disabled = picked.size === 0; }
}

function drawHistory(list) {
  const body = $('history');
  if (!list.length) {
    const tr = el('tr'); const td = el('td', 'empty', 'None yet.'); td.colSpan = 8; tr.append(td);
    body.replaceChildren(tr);
    return;
  }
  const label = { sending: 'sending', done: 'done', stopped: 'stopped' };
  body.replaceChildren(...list.map((a) => {
    const tr = el('tr');
    const act = el('td');
    if (a.status === 'sending') {
      const stop = el('button', 'ghost', 'Stop');
      stop.type = 'button';
      stop.addEventListener('click', async () => {
        if (!window.confirm('Stop this announcement? Whoever hasn\'t got it yet won\'t.')) return;
        try { const r = await api(`/api/announcements/${a.id}/stop`, {}); show($('a-msg'), r.message); await loadAnnounce(); }
        catch (e) { if (!ended) show($('a-msg'), e.message, true); }
      });
      act.append(stop);
    }
    tr.append(el('td', '', when(a.created_at)), el('td', 'wrap', a.subject + (a.files ? ` (${a.files} file${a.files > 1 ? 's' : ''})` : '')),
      el('td', '', label[a.status] || a.status), el('td', '', String(a.sent)), el('td', '', String(a.pending)),
      el('td', a.failed ? 'ev-problem' : '', String(a.failed)), el('td', '', String(a.skipped + a.stopped)), act);
    return tr;
  }));
}

document.addEventListener('DOMContentLoaded', () => {
  $('refresh').addEventListener('click', () => { refresh(); if (tab === 'logs') loadLogs().catch(fail); if (tab === 'announce') loadAnnounce().catch(fail); });
  for (const b of document.querySelectorAll('.tab')) b.addEventListener('click', () => showTab(b.dataset.tab));

  fillEventFilter();
  let lt;
  const relog = () => { logPage = 0; loadLogs().catch(fail); };
  $('log-search').addEventListener('input', () => { clearTimeout(lt); lt = setTimeout(relog, 250); });
  $('log-event').addEventListener('change', relog);
  $('log-problems').addEventListener('change', relog);
  $('log-older').addEventListener('click', () => { logPage += 1; loadLogs().catch(fail); });
  $('log-newer').addEventListener('click', () => { logPage = Math.max(0, logPage - 1); loadLogs().catch(fail); });

  $('r-search').addEventListener('input', drawPeople);
  $('r-all').addEventListener('click', () => { for (const p of people) if (eligible(p)) picked.add(p.account); drawPeople(); });
  $('r-none').addEventListener('click', () => { picked.clear(); drawPeople(); });
  $('a-queue').addEventListener('change', drawPlan);
  $('a-files').addEventListener('change', () => {
    const add = [...$('a-files').files];
    $('a-files').value = '';
    const all = [...files, ...add];
    if (all.length > 5) { show($('a-msg'), 'Attach at most 5 files.', true); return; }
    if (all.reduce((s, f) => s + f.size, 0) > 10 * 1024 * 1024) { show($('a-msg'), 'Attachments can be 10 MB in total at most.', true); return; }
    files = all;
    show($('a-msg'), '');
    drawFiles();
  });
  $('a-test').addEventListener('click', (e) => sendTest(e.currentTarget));
  $('a-send').addEventListener('click', (e) => sendAll(e.currentTarget));
  // While announcements are open, keep the counts fresh.
  setInterval(() => { if (tab === 'announce' && !ended) api('/api/announcements').then(drawHistory, () => {}); }, 15000);

  $('d-annoff').addEventListener('change', async (e) => {
    const box = e.currentTarget;
    box.disabled = true;
    try {
      const r = await api('/api/user/' + encodeURIComponent(current.account) + '/announcements', { off: box.checked });
      show($('d-msg'), r.message);
      refresh();
    } catch (err) { box.checked = !box.checked; if (!ended) show($('d-msg'), err.message, true); }
    finally { box.disabled = false; }
  });
  let timer;
  $('search').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(refresh, 250); });
  $('d-close').addEventListener('click', () => $('detail').close());

  $('d-suspend-btn').addEventListener('click', async (e) => {
    const reason = $('d-reason').value.trim() || null;
    if (await act('/api/suspend', { account: current.account, reason }, e.currentTarget)) openDetail(current.account, true);
  });
  $('d-unsuspend-btn').addEventListener('click', async (e) => {
    if (await act('/api/unsuspend', { account: current.account }, e.currentTarget)) openDetail(current.account, true);
  });
  $('d-confirm').addEventListener('input', () => {
    $('d-delete-btn').disabled = $('d-confirm').value.trim().toLowerCase() !== (current?.email || '').toLowerCase();
  });
  $('d-delete-btn').addEventListener('click', async (e) => {
    const ok = await act('/api/delete', { account: current.account, confirm_email: $('d-confirm').value, reason: $('d-del-reason').value.trim() || null }, e.currentTarget);
    if (ok) {
      const msg = $('d-msg').textContent;
      $('detail').close();
      show($('banner'), msg);
    }
  });

  refresh();
});
