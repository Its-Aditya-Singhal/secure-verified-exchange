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

async function loadStats() {
  const s = await api('/api/stats');
  const cards = [
    ['Accounts', s.accounts, `${s.accounts_7d} new this week · ${s.accounts_30d} this month`],
    ['Sign-in', `${s.email_accounts} / ${s.google_accounts}`, 'email / Google'],
    ['Suspended', s.suspended, ''],
    ['Files sent', s.files, `${s.files_7d} this week`],
    ['Opens', s.opens_7d, 'in the last 7 days'],
    ['Waiting for approval', s.pending_approvals, ''],
    ['Database', `${(s.database_bytes / 1e6).toFixed(1)} MB`, ''],
  ];
  const box = $('stats');
  box.replaceChildren(...cards.map(([k, v, sub]) => {
    const c = el('div', 'card');
    c.append(el('div', 'v', String(v)), el('div', 'k', k));
    if (sub) c.append(el('div', 's', sub));
    return c;
  }));
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

document.addEventListener('DOMContentLoaded', () => {
  $('refresh').addEventListener('click', refresh);
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
