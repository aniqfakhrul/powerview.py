/* =====================================================================
   powerview.py web ui — shared runtime  (classic compact dark)
   App shell (topbar / rail / status), hyperscript, API client, sortable
   grid, property views, toasts, tweaks. Exposed as window.PV.
   ===================================================================== */
(function () {
"use strict";

/* ───────── hyperscript ───────── */
function add(el, kids) {
	for (const k of kids) {
		if (k == null || k === false || k === true) continue;
		if (Array.isArray(k)) add(el, k);
		else el.appendChild(k.nodeType ? k : document.createTextNode(String(k)));
	}
}
function h(tag, attrs, ...kids) {
	let cls = '', id = '';
	tag = (tag || 'div')
		.replace(/#([\w-]+)/g, (_, v) => { id = v; return ''; })
		.replace(/\.([\w-]+)/g, (_, v) => { cls += (cls ? ' ' : '') + v; return ''; });
	const el = document.createElement(tag || 'div');
	if (id) el.id = id;
	if (cls) el.className = cls;
	if (attrs && (attrs.nodeType || Array.isArray(attrs) || typeof attrs !== 'object')) {
		kids.unshift(attrs); attrs = null;
	}
	if (attrs) for (const k in attrs) {
		const v = attrs[k];
		if (v == null || v === false) continue;
		if (k === 'class') el.className = (el.className ? el.className + ' ' : '') + v;
		else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
		else if (k === 'html') el.innerHTML = v;
		else if (k === 'data' && typeof v === 'object') for (const d in v) el.dataset[d] = v[d];
		else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
		else el.setAttribute(k, v);
	}
	add(el, kids);
	return el;
}
const $  = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const clear = (el) => { while (el && el.firstChild) el.removeChild(el.firstChild); return el; };

/* ───────── API ───────── */
async function req(path, opts) {
	const r = await fetch(path, opts);
	let data = null;
	try { data = await r.json(); } catch (e) {}
	if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
	return data;
}
const api = {
	get:  (p) => req(p),
	post: (p, b) => req(p, { method: 'POST', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(b || {}) }),
	op:   (verb, method, params) => api.post('/api/' + verb + '/' + method, params || {}),
	execute: (cmd) => api.post('/api/execute', { command: cmd })
};

/* ───────── toasts ───────── */
let toastHost;
function toast(kind, msg) {
	if (!toastHost) { toastHost = h('div.toast-stack'); document.body.appendChild(toastHost); }
	const t = h('div.toast.' + kind, h('span.grow', msg),
		h('span.x', { onclick: () => t.remove() }, '✕'));
	toastHost.appendChild(t);
	setTimeout(() => t.remove(), 5500);
}

/* ───────── value formatting ───────── */
function attr(a, k) { const v = a && a[k]; return Array.isArray(v) ? v[0] : v; }
function fmtVal(v) {
	if (v == null || v === '') return '—';
	if (Array.isArray(v)) return v.length ? v.map(fmtVal).join(', ') : '—';
	if (typeof v === 'object') return JSON.stringify(v);
	const s = String(v);
	if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(s)) return '<binary \u00b7 ' + s.length + ' bytes>';
	return s;
}
/* userAccountControl comes from the API already decoded into an array of
   flag-name strings; fall back to decoding a raw integer if needed. */
const UAC_BITS = { 1:'SCRIPT', 2:'ACCOUNTDISABLE', 8:'HOMEDIR_REQUIRED', 16:'LOCKOUT',
	32:'PASSWD_NOTREQD', 64:'PASSWD_CANT_CHANGE', 128:'ENCRYPTED_TEXT_PWD_ALLOWED',
	256:'TEMP_DUPLICATE_ACCOUNT', 512:'NORMAL_ACCOUNT', 2048:'INTERDOMAIN_TRUST_ACCOUNT',
	4096:'WORKSTATION_TRUST_ACCOUNT', 8192:'SERVER_TRUST_ACCOUNT', 65536:'DONT_EXPIRE_PASSWORD',
	131072:'MNS_LOGON_ACCOUNT', 262144:'SMARTCARD_REQUIRED', 524288:'TRUSTED_FOR_DELEGATION',
	1048576:'NOT_DELEGATED', 2097152:'USE_DES_KEY_ONLY', 4194304:'DONT_REQ_PREAUTH',
	8388608:'PASSWORD_EXPIRED', 16777216:'TRUSTED_TO_AUTH_FOR_DELEGATION',
	67108864:'PARTIAL_SECRETS_ACCOUNT' };
function uacFlags(v) {
	if (v == null) return [];
	if (Array.isArray(v)) {
		if (!v.length) return [];
		if (!/^\d+$/.test(String(v[0]))) return v.map(String);
		v = v[0];
	}
	const n = parseInt(v, 10);
	if (isNaN(n)) return [];
	return Object.keys(UAC_BITS).filter(b => n & b).map(b => UAC_BITS[b]);
}

/* ───────── sortable grid table ───────── */
function grid(columns, opts) {
	opts = opts || {};
	let rows = [], sortKey = opts.sort || null, sortDir = 'asc', selId = null;
	const tbody = h('tbody');
	const thead = h('thead');
	const table = h('table.grid', thead, tbody);
	const wrap = h('div.table-wrap', table);

	function headerRow() {
		clear(thead);
		thead.appendChild(h('tr', columns.map(c => {
			const active = sortKey === c.key;
			return h('th', {
				class: active ? 'sorted' : '',
				style: c.w ? { width: c.w + 'px' } : null,
				onclick: () => {
					if (sortKey === c.key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
					else { sortKey = c.key; sortDir = 'asc'; }
					render();
				}
			}, c.label, h('span.sort', active ? (sortDir === 'asc' ? '▲' : '▼') : '↕'));
		})));
	}
	function render() {
		headerRow();
		let view = rows.slice();
		if (sortKey) {
			view.sort((a, b) => {
				let av = a[sortKey], bv = b[sortKey];
				if (typeof av === 'boolean') av = av ? 1 : 0;
				if (typeof bv === 'boolean') bv = bv ? 1 : 0;
				if (av == null) av = ''; if (bv == null) bv = '';
				let r;
				if (typeof av === 'number' && typeof bv === 'number') r = av - bv;
				else r = String(av).localeCompare(String(bv));
				return sortDir === 'asc' ? r : -r;
			});
		}
		clear(tbody);
		if (!view.length) {
			tbody.appendChild(h('tr', h('td', { colspan: columns.length },
				h('div.empty', opts.empty || 'no rows'))));
			return;
		}
		view.forEach(row => {
			const id = opts.rowKey ? opts.rowKey(row) : null;
			const selectRow = () => {
				if (id == null) return;
				selId = id;
				$$('tr.selected', tbody).forEach(x => x.classList.remove('selected'));
				tr.classList.add('selected');
			};
			const tr = h('tr', {
				class: (id != null && id === selId) ? 'selected' : '',
				onclick: () => { selectRow(); if (opts.onRow) opts.onRow(row, tr); },
				oncontextmenu: opts.onRowContext
					? (ev) => { ev.preventDefault(); selectRow(); opts.onRowContext(row, ev); }
					: null
			}, columns.map(c => {
				const v = row[c.key];
				let cell = c.render ? c.render(v, row) : (v == null || v === '' ? h('span.muted', '—') : String(v));
				const td = h('td', { style: c.color ? { color: c.color(v, row) } : null }, cell);
				if (c.title !== false && typeof cell === 'string') td.title = cell;
				return td;
			}));
			tbody.appendChild(tr);
		});
	}
	render();
	return {
		el: wrap,
		setData(r) { rows = r || []; render(); },
		setSelected(id) { selId = id; render(); },
		get rows() { return rows; },
		get selectedId() { return selId; }
	};
}

/* ───────── tag / page head / property view ───────── */
function tag(text, color) { return h('span', { class: 'tag ' + (color || 'gray') }, text); }

function pageHead(title, crumbs, toolbar) {
	return h('div.page-head',
		h('span.title', title),
		crumbs != null ? h('span.crumbs', '/ ' + crumbs) : null,
		h('span.grow'),
		h('div.toolbar', toolbar || []));
}
function searchField(onChange, placeholder, width) {
	const inp = h('input', { placeholder: placeholder || 'filter…',
		oninput: () => onChange(inp.value) });
	const f = h('div.field', { style: { width: (width || 220) + 'px' } },
		h('span.glyph', '⌕'), inp);
	f.input = inp;
	return f;
}
function btn(label, kind, onclick) {
	return h('button', { class: 'btn' + (kind ? ' ' + kind : ''), onclick: onclick || null }, label);
}

/* property panel: groups = [{title, open, rows:[{k,v,cls}], body}] */
function propRow(k, v, cls) {
	return h('div.row', h('span.k', k), h('span', { class: 'v ' + (cls || '') }, v));
}
function propGroup(title, body, open) {
	const wrapBody = h('div', body);
	if (open === false) wrapBody.hidden = true;
	const chev = h('span.chev', open === false ? '▸' : '▾');
	const head = h('div.group-head', { onclick: () => {
		wrapBody.hidden = !wrapBody.hidden;
		chev.textContent = wrapBody.hidden ? '▸' : '▾';
	}}, chev, title);
	return h('div.group', head, wrapBody);
}
function propsView(groups) {
	return h('div.props', groups.map(g => propGroup(g.title,
		g.body || (g.rows || []).map(r => propRow(r.k, r.v, r.cls)), g.open)));
}

/* loading overlay around a positioned container */
function withSpinner(container) {
	container.style.position = container.style.position || 'relative';
	const ov = h('div.overlay-spinner', h('div.spinner.lg'));
	container.appendChild(ov);
	return () => ov.remove();
}

/* run a powerview command, surface result via toast */
async function runCmd(cmd) {
	toast('info', '$ ' + cmd);
	try {
		const res = await api.execute(cmd);
		const out = res && res.result;
		const n = Array.isArray(out) ? out.length : null;
		toast('success', n != null ? (n + ' result(s) — ' + cmd) : ('done — ' + cmd));
		return res;
	} catch (e) { toast('error', e.message); throw e; }
}

/* ───────── navigation ───────── */
const NAV = [
	{ sec: 'ENUM', id: 'explorer',  label: 'Explorer',    href: '/',          icn: '▤' },
	{ sec: 'ENUM', id: 'dashboard', label: 'Dashboard',   href: '/dashboard', icn: '◧' },
	{ sec: 'ENUM', id: 'graph',     label: 'Graph',       href: '/graph',     icn: '◌' },
	{ sec: 'OBJECTS', id: 'users',     label: 'Users',       href: '/users',     icn: 'U' },
	{ sec: 'OBJECTS', id: 'computers', label: 'Computers',   href: '/computers', icn: 'C' },
	{ sec: 'OBJECTS', id: 'groups',    label: 'Groups',      href: '/groups',    icn: 'G' },
	{ sec: 'OBJECTS', id: 'dns',       label: 'DNS',         href: '/dns',       icn: '≡' },
	{ sec: 'OBJECTS', id: 'ca',        label: 'CA',          href: '/ca',        icn: '♦' },
	{ sec: 'OBJECTS', id: 'ous',       label: 'OUs',         href: '/ou',        icn: '▸' },
	{ sec: 'OBJECTS', id: 'gpos',      label: 'GPOs',        href: '/gpo',       icn: '◆' },
	{ sec: 'OPS', id: 'smb',      label: 'SMB Browser', href: '/smb',      icn: '▦' },
	{ sec: 'OPS', id: 'utils',    label: 'Utils',       href: '/utils',    icn: '✦' },
	{ sec: 'OPS', id: 'settings', label: 'Settings',    href: '/settings', icn: '⚙' }
];
function buildRail() {
	const rail = $('#rail'); if (!rail) return;
	const page = document.body.getAttribute('data-page');
	let lastSec = null;
	NAV.forEach(n => {
		if (n.sec !== lastSec) { rail.appendChild(h('div.section-title', n.sec)); lastSec = n.sec; }
		rail.appendChild(h('a', { class: 'nav-item' + (n.id === page ? ' active' : ''), href: n.href },
			h('span.icn', n.icn), h('span', n.label)));
	});
	const tp = $('#tb-page');
	if (tp) { const cur = NAV.find(n => n.id === page); tp.textContent = cur ? '› ' + cur.label : ''; }
}

/* ───────── connection / status bar ───────── */
async function poll() {
	const conn = $('#tb-conn'), status = $('#status');
	try {
		const c = await api.get('/api/connectioninfo');
		const ok = c.status === 'OK';
		const proto = (c.protocol || 'ldap').toUpperCase();
		if (conn) {
			clear(conn);
			conn.append(
				h('span', { class: 'pill ' + (ok ? 'ok' : 'err') }, '● ' + proto),
				h('span', c.ldap_address || '—'),
				h('span.muted', '|'),
				h('span', (c.domain ? c.domain + '\\' : '') + (c.username || '—')),
				h('span.muted', '|'),
				h('span', { class: 'pill' }, 'ns ' + (c.nameserver || '—')));
		}
		if (status) {
			clear(status);
			status.append(
				h('span', h('span', { class: ok ? 'ok' : 'err' }, '●'), ok ? ' connected' : ' disconnected'),
				h('span.sep', '│'),
				h('span', c.domain || '—'),
				h('span.sep', '│'),
				h('span', proto + ' ' + (c.ldap_address || '')),
				h('span.grow'),
				logToggleItem(),
				h('span.sep', '│'),
				h('span', 'powerview.py web'),
				h('span.sep', '│'),
				h('span', h('kbd', '1–0'), ' nav'));
		}
	} catch (e) {
		if (conn) { clear(conn); conn.append(h('span', { class: 'pill err' }, '● offline')); }
		if (status) {
			clear(status);
			status.append(
				h('span', h('span.err', '●'), ' disconnected'),
				h('span.grow'), logToggleItem());
		}
	}
}
/* clickable `>_ Output` affordance shown inside the status bar */
function logToggleItem() {
	return h('span.status-log-toggle', {
		title: 'Toggle the log panel', onclick: e => { e.stopPropagation(); toggleLogPanel(); }
	}, h('span.mono', '>_'), ' Output');
}

/* ───────── tweaks (accent / density / font / background) ───────── */
const ACCENTS = ['#5fd1b3', '#7aa2f7', '#e6c07a', '#e06c75', '#c678dd', '#98c379'];
const BG_TONES = {
	'true-black': ['#000000', '#0a0c0f', '#101317', '#16191e'],
	'near-black': ['#0b0d10', '#111418', '#161a20', '#1c2128'],
	'slate':      ['#10141a', '#161b22', '#1b2027', '#222831']
};
function loadTweaks() {
	let t = { accent: '#5fd1b3', density: 'compact', fontScale: 100, background: 'near-black' };
	try { Object.assign(t, JSON.parse(localStorage.getItem('pv-tweaks') || '{}')); } catch (e) {}
	return t;
}
function applyTweaks(t) {
	const r = document.documentElement.style;
	r.setProperty('--accent', t.accent);
	const m = t.accent.replace('#', '');
	r.setProperty('--accent-bg', 'rgba(' + parseInt(m.slice(0,2),16) + ',' +
		parseInt(m.slice(2,4),16) + ',' + parseInt(m.slice(4,6),16) + ',0.08)');
	const s = t.fontScale / 100;
	r.setProperty('--fs-xs', (10.5*s)+'px'); r.setProperty('--fs-sm', (11.5*s)+'px');
	r.setProperty('--fs', (12.5*s)+'px'); r.setProperty('--fs-md', (13.5*s)+'px');
	r.setProperty('--fs-lg', (15*s)+'px');
	const dh = t.density === 'comfortable' ? [26,24] : t.density === 'ultra' ? [19,17] : [22,20];
	r.setProperty('--row-h', dh[0]+'px'); r.setProperty('--row-h-sm', dh[1]+'px');
	const bg = BG_TONES[t.background] || BG_TONES['near-black'];
	r.setProperty('--bg', bg[0]); r.setProperty('--panel', bg[1]);
	r.setProperty('--panel-2', bg[2]); r.setProperty('--panel-3', bg[3]);
	try { localStorage.setItem('pv-tweaks', JSON.stringify(t)); } catch (e) {}
}
let tweaks = loadTweaks();
function openTweaks(anchor) {
	$$('.popover').forEach(p => p.remove());
	const seg = (val, options, on) => h('div.seg-ctl', options.map(o =>
		h('button', { class: o === val ? 'on' : '', onclick: () => on(o) }, o)));
	const pop = h('div.popover',
		h('div.pop-row', h('div.pl', 'Accent'),
			h('div.swatches', ACCENTS.map(c => h('div', {
				class: 'sw' + (c === tweaks.accent ? ' on' : ''),
				style: { background: c },
				onclick: () => { tweaks.accent = c; applyTweaks(tweaks); openTweaks(anchor); }
			})))),
		h('div.pop-row', h('div.pl', 'Density'),
			seg(tweaks.density, ['ultra','compact','comfortable'],
				v => { tweaks.density = v; applyTweaks(tweaks); openTweaks(anchor); })),
		h('div.pop-row', h('div.pl', 'Font scale — ' + tweaks.fontScale + '%'),
			seg(String(tweaks.fontScale), ['85','100','115','130'],
				v => { tweaks.fontScale = +v; applyTweaks(tweaks); openTweaks(anchor); })),
		h('div.pop-row', h('div.pl', 'Background'),
			seg(tweaks.background, ['true-black','near-black','slate'],
				v => { tweaks.background = v; applyTweaks(tweaks); openTweaks(anchor); })));
	const r = anchor.getBoundingClientRect();
	pop.style.left = r.left + 'px';
	pop.style.top = (r.bottom + 2) + 'px';
	document.body.appendChild(pop);
	setTimeout(() => {
		document.addEventListener('mousedown', function off(e) {
			if (!pop.contains(e.target) && e.target !== anchor) { pop.remove(); document.removeEventListener('mousedown', off); }
		});
	}, 0);
}

/* ───────── VSCode-style docked log panel ─────────
   Lives in the app shell so it is available on every page. Toggled from the
   status bar; fetches the existing /api/logs JSON endpoint. */
const LOG_COLOR = { DEBUG: 'var(--muted)', INFO: 'var(--blue)',
	WARNING: 'var(--yellow)', ERROR: 'var(--red)', CRITICAL: 'var(--red)', SUCCESS: 'var(--accent)' };
let panelEl = null, panelTabsEl = null, panelBodyEl = null;
let panelOpen = false, panelH = 280, panelDrag = null;
let logBodyEl = null, logPollTimer = null;
const panelTabs = [];           /* {id,label,icon,body,closable,onClose} */
let activeTabId = null;

function buildBottomPanel() {
	const appEl = $('.app');
	if (!appEl) return null;
	const resize = h('div.drawer-resize', { title: 'drag to resize' });
	resize.addEventListener('mousedown', e => { panelDrag = { y: e.clientY, h: panelH }; e.preventDefault(); });
	panelTabsEl = h('div.drawer-tabs');
	panelBodyEl = h('div.bottom-panel-body');
	panelEl = h('div.log-panel', resize, panelTabsEl, panelBodyEl);
	panelEl.hidden = true;
	appEl.appendChild(panelEl);
	logBodyEl = h('div.terminal');
	registerTab({ id: 'output', label: 'Output', icon: '>_', body: logBodyEl, closable: false });
	registerTab({ id: 'cli', label: 'CLI', icon: '$', body: buildCliPane(), closable: false });
	return panelEl;
}

function registerTab(tab) {
	const existing = panelTabs.find(t => t.id === tab.id);
	if (existing) return existing;
	tab.body.style.display = 'none';
	panelTabs.push(tab);
	if (panelBodyEl) panelBodyEl.appendChild(tab.body);
	return tab;
}

function renderTabs() {
	if (!panelTabsEl) return;
	clear(panelTabsEl);
	panelTabs.forEach(t => {
		panelTabsEl.appendChild(h('div', { class: 'drawer-tab' + (t.id === activeTabId ? ' active' : ''),
			onclick: () => showTab(t.id) },
			t.icon ? h('span.dollar', { style: { color: 'var(--accent)' } }, t.icon) : null,
			h('span', t.label),
			t.closable ? h('button.x', { title: 'close tab',
				onclick: e => { e.stopPropagation(); removeTab(t.id); } }, '✕') : null));
	});
	const actions = h('div.drawer-actions', { style: { marginLeft: 'auto', paddingRight: '6px' } });
	if (activeTabId === 'output') {
		actions.appendChild(h('button.drawer-action', { title: 'Refresh logs', onclick: () => loadLogPanel() }, '⟲ Refresh'));
		actions.appendChild(h('button.drawer-action', { title: 'Clear view', onclick: () => clear(logBodyEl) }, 'Clear'));
	}
	actions.appendChild(h('button.drawer-action', { title: 'Close panel (Esc)', onclick: () => closePanel() }, '✕'));
	panelTabsEl.appendChild(actions);
}

function showTab(id) {
	if (!panelEl) buildBottomPanel();
	const tab = panelTabs.find(t => t.id === id);
	if (!tab) return;
	activeTabId = id;
	panelTabs.forEach(t => { t.body.style.display = t.id === id ? '' : 'none'; });
	openPanel();
	renderTabs();
	if (id === 'output') startLogPoll(); else stopLogPoll();
	if (id === 'cli' && cliInputEl) cliInputEl.focus();
}

function removeTab(id) {
	const i = panelTabs.findIndex(t => t.id === id);
	if (i < 0 || !panelTabs[i].closable) return;
	const tab = panelTabs.splice(i, 1)[0];
	if (tab.body.parentNode) tab.body.parentNode.removeChild(tab.body);
	if (tab.onClose) { try { tab.onClose(); } catch (e) {} }
	if (activeTabId === id) {
		const next = panelTabs[panelTabs.length - 1];
		if (next) showTab(next.id); else closePanel();
	} else if (panelOpen) renderTabs();
}

function openPanel() {
	if (!panelEl) buildBottomPanel();
	panelOpen = true;
	panelEl.hidden = false;
	panelEl.style.height = panelH + 'px';
}
function closePanel() {
	if (!panelEl) return;
	panelOpen = false;
	panelEl.hidden = true;
	stopLogPoll();
}

function startLogPoll() {
	loadLogPanel();
	if (logPollTimer) clearInterval(logPollTimer);
	logPollTimer = setInterval(loadLogPanel, 15000);
}
function stopLogPoll() {
	if (logPollTimer) { clearInterval(logPollTimer); logPollTimer = null; }
}

/* ───────── CLI tab — interactive PowerView command runner ───────── */
let cliHistEl = null, cliInputEl = null, cliHintEl = null, cliCommands = null;
const cliHistory = [];
let cliHistIdx = 0, cliDraft = '';

const CLI_COL_PRIORITY = ['sAMAccountName', 'name', 'cn', 'displayName', 'dNSHostName',
	'distinguishedName', 'objectSid', 'description', 'operatingSystem', 'adminCount',
	'userAccountControl', 'memberOf', 'lastLogon', 'lastLogonTimestamp', 'pwdLastSet',
	'servicePrincipalName'];

function buildCliPane() {
	cliHistEl = h('div.cli-history');
	cliHintEl = h('div.cli-hint');
	cliHintEl.hidden = true;
	cliInputEl = h('input.cli-input', { type: 'text', spellcheck: 'false', autocomplete: 'off',
		placeholder: 'type a PowerView command — Tab completes · ↑/↓ history · Enter runs' });
	cliInputEl.addEventListener('input', () => cliHint(''));
	cliInputEl.addEventListener('keydown', e => {
		if (e.key === 'Enter') {
			const v = cliInputEl.value.trim();
			if (!v) return;
			cliInputEl.value = '';
			cliHint('');
			cliExec(v);
		} else if (e.key === 'Tab') {
			e.preventDefault();
			cliComplete();
		} else if (e.key === 'ArrowUp') {
			if (!cliHistory.length) return;
			e.preventDefault();
			if (cliHistIdx === cliHistory.length) cliDraft = cliInputEl.value;
			cliHistIdx = Math.max(0, cliHistIdx - 1);
			cliSetInput(cliHistory[cliHistIdx]);
		} else if (e.key === 'ArrowDown') {
			if (cliHistIdx >= cliHistory.length) return;
			e.preventDefault();
			cliHistIdx++;
			cliSetInput(cliHistIdx >= cliHistory.length ? cliDraft : cliHistory[cliHistIdx]);
		}
	});
	api.get('/api/commands').then(c => { cliCommands = c || {}; }).catch(() => { cliCommands = {}; });
	return h('div.cli-pane', cliHistEl, cliHintEl,
		h('div.cli-prompt', h('span.cli-ps', 'PV ›'), cliInputEl));
}

function cliHint(text) {
	if (!cliHintEl) return;
	cliHintEl.textContent = text || '';
	cliHintEl.hidden = !text;
}

function cliCommonPrefix(arr) {
	if (!arr.length) return '';
	let p = arr[0];
	for (let i = 1; i < arr.length; i++) {
		const s = arr[i];
		let j = 0;
		while (j < p.length && j < s.length && p[j].toLowerCase() === s[j].toLowerCase()) j++;
		p = p.slice(0, j);
		if (!p) break;
	}
	return p;
}

function cliComplete() {
	if (!cliCommands) return;
	const val = cliInputEl.value;
	const lead = val.replace(/\S*$/, '');
	const token = val.slice(lead.length);
	const before = lead.trim().split(/\s+/).filter(Boolean);
	let candidates;
	if (before.length === 0) {
		candidates = Object.keys(cliCommands)
			.filter(c => c.toLowerCase().startsWith(token.toLowerCase()));
	} else {
		if (token && token[0] !== '-') { cliHint(''); return; }
		const key = Object.keys(cliCommands)
			.find(c => c.toLowerCase() === before[0].toLowerCase());
		const flags = key && Array.isArray(cliCommands[key]) ? cliCommands[key] : [];
		candidates = flags.filter(f => f.toLowerCase().startsWith(token.toLowerCase()));
	}
	if (!candidates.length) { cliHint(''); return; }
	if (candidates.length === 1) {
		cliInputEl.value = lead + candidates[0] + ' ';
		cliHint('');
	} else {
		const prefix = cliCommonPrefix(candidates);
		if (prefix.length > token.length) cliInputEl.value = lead + prefix;
		cliHint(candidates.join('   '));
	}
	const n = cliInputEl.value.length;
	cliInputEl.setSelectionRange(n, n);
}

function cliSetInput(v) {
	cliInputEl.value = v || '';
	const n = cliInputEl.value.length;
	cliInputEl.setSelectionRange(n, n);
}

function cliCopy(text) {
	try {
		navigator.clipboard.writeText(text);
		toast('success', 'copied to clipboard');
	} catch (e) { toast('error', 'clipboard unavailable'); }
}

function cliSummary(rows, shown, total, ms) {
	let s = rows + ' result(s)';
	if (total > shown) s += ' · ' + shown + ' of ' + total + ' columns';
	if (ms != null) s += ' · ' + ms + 'ms';
	return h('div.cli-summary', s);
}

function cliRenderResult(out, ms) {
	if (out == null) return h('div.cli-msg', '(no output)');
	if (!Array.isArray(out)) return h('div.cli-msg', fmtVal(out));
	if (out.length && out.every(e => e && typeof e === 'object' && Array.isArray(e.attributes)))
		out = out.reduce((acc, e) => acc.concat(e.attributes), []);
	if (!out.length) return h('div.cli-msg', '(0 results)');
	const entryMode = out[0] && typeof out[0] === 'object' && out[0].attributes
		&& !Array.isArray(out[0].attributes);
	const objOf = e => entryMode ? (e.attributes || {}) : e;
	if (typeof out[0] !== 'object')
		return h('div', cliSummary(out.length, 0, 0, ms),
			h('div.cli-out', h('table.grid', h('tbody', out.map(x => h('tr', h('td', fmtVal(x))))))));
	const cols = [];
	out.slice(0, 50).forEach(e => Object.keys(objOf(e) || {}).forEach(k => {
		if (cols.indexOf(k) < 0) cols.push(k);
	}));
	cols.sort((a, b) => {
		const ia = CLI_COL_PRIORITY.indexOf(a), ib = CLI_COL_PRIORITY.indexOf(b);
		if (ia < 0 && ib < 0) return 0;
		if (ia < 0) return 1;
		if (ib < 0) return -1;
		return ia - ib;
	});
	const use = cols.slice(0, 8);
	return h('div', cliSummary(out.length, use.length, cols.length, ms),
		h('div.cli-out',
			h('table.grid',
				h('thead', h('tr', use.map(c => h('th', c)))),
				h('tbody', out.map(e => {
					const o = objOf(e) || {};
					return h('tr', use.map((k, i) => {
						const v = fmtVal(o[k]);
						return h('td', { title: v,
							style: { color: i === 0 ? 'var(--accent)' : 'var(--text)' } }, v);
					}));
				})))));
}

async function cliExec(cmd) {
	if (!cliHistEl) return;
	if (cliHistory[cliHistory.length - 1] !== cmd) cliHistory.push(cmd);
	cliHistIdx = cliHistory.length;
	cliDraft = '';
	const body = h('div.cli-body', h('span.cli-msg', 'running…'));
	const acts = h('span.cli-actions');
	cliHistEl.appendChild(h('div.cli-entry',
		h('div.cli-cmd', h('span.cli-ps', 'PV ›'), ' ' + cmd, acts), body));
	cliHistEl.scrollTop = cliHistEl.scrollHeight;
	const t0 = performance.now();
	let resultData = null, ok = false;
	try {
		const res = await runCmd(cmd);
		resultData = res && res.result; ok = true;
		clear(body); add(body, [cliRenderResult(resultData, Math.round(performance.now() - t0))]);
	} catch (e) {
		clear(body);
		body.appendChild(h('div.cli-msg.cli-err', e.message));
	}
	add(acts, [
		h('button.cli-act', { title: 'Re-run', onclick: () => cliExec(cmd) }, '↻'),
		h('button.cli-act', { title: 'Edit in prompt',
			onclick: () => { cliSetInput(cmd); cliInputEl.focus(); } }, '✎'),
		h('button.cli-act', { title: 'Copy',
			onclick: () => cliCopy(ok && resultData != null ? JSON.stringify(resultData, null, 2) : cmd) }, '⧉')
	]);
	cliHistEl.scrollTop = cliHistEl.scrollHeight;
}

const cli = {
	run: function (cmd) {
		if (!panelEl) buildBottomPanel();
		showTab('cli');
		cliExec(cmd);
	}
};
function renderLogLines(logs) {
	if (!logBodyEl) return;
	clear(logBodyEl);
	if (!logs || !logs.length) {
		logBodyEl.appendChild(h('div.muted.mono.sm', '(no log entries)'));
		return;
	}
	/* API returns most-recent-first — reverse to terminal order (oldest top) */
	logs.slice().reverse().forEach(l => {
		const lt = (l.log_type || 'INFO').toUpperCase();
		logBodyEl.appendChild(h('div.line',
			h('span.ts', l.timestamp || ''),
			l.user ? h('span.log-user', String(l.user) + ' ') : null,
			h('span', { style: { color: LOG_COLOR[lt] || 'var(--text-2)' } },
				'[' + lt + '] ' + (l.debug_message || ''))));
	});
	logBodyEl.scrollTop = logBodyEl.scrollHeight;
}
async function loadLogPanel() {
	if (!logBodyEl) return;
	try {
		const data = await api.get('/api/logs?page=1&limit=100');
		renderLogLines(data && data.logs);
	} catch (e) {
		clear(logBodyEl);
		logBodyEl.appendChild(h('div.line', h('span', { style: { color: 'var(--red)' } },
			'[ERROR] ' + e.message)));
	}
}
function toggleLogPanel(force) {
	if (!panelEl) buildBottomPanel();
	const want = (force == null) ? !panelOpen : !!force;
	if (want) showTab('output');
	else closePanel();
}

const bottomPanel = {
	addTab: function (t) { const tab = registerTab(t); if (panelOpen) renderTabs(); return tab; },
	removeTab: removeTab,
	showTab: showTab,
	open: openPanel,
	close: closePanel,
	has: function (id) { return panelTabs.some(t => t.id === id); },
	isOpen: function () { return panelOpen; }
};

window.addEventListener('mousemove', e => {
	if (!panelDrag || !panelEl) return;
	panelH = Math.max(120, Math.min(640, panelDrag.h + (panelDrag.y - e.clientY)));
	panelEl.style.height = panelH + 'px';
});
window.addEventListener('mouseup', () => { panelDrag = null; });
document.addEventListener('keydown', e => {
	if (e.key === 'Escape' && panelOpen) { closePanel(); return; }
	if ((e.ctrlKey || e.metaKey) && e.key === '`') {
		e.preventDefault();
		if (panelOpen) closePanel(); else showTab('cli');
	}
});
/* clicking outside the panel closes it — except the status bar (its own
   toggle) and quick-query cards (which reopen it via the CLI). */
document.addEventListener('mousedown', e => {
	if (!panelOpen || !panelEl || panelEl.contains(e.target)) return;
	if (e.target.closest && (e.target.closest('#status') || e.target.closest('.qq-card'))) return;
	closePanel();
});

/* ───────── shell init ───────── */
function initShell() {
	applyTweaks(tweaks);
	buildRail();
	poll();
	setInterval(poll, 15000);
	buildBottomPanel();
	const statusBar = $('#status');
	if (statusBar) statusBar.addEventListener('click', () => toggleLogPanel());

	const view = $('.menu button[data-menu="view"]');
	if (view) view.onclick = () => openTweaks(view);
	$$('.menu button').forEach(b => { if (b.dataset.menu !== 'view') b.onclick = () => toast('info', b.textContent + ' menu — not wired'); });

	document.addEventListener('keydown', e => {
		if (/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
		const n = parseInt(e.key, 10);
		if (!isNaN(n)) {
			const order = ['explorer','dashboard','graph','users','computers','groups','dns','ca','ous','gpos'];
			const item = NAV.find(x => x.id === order[n === 0 ? 9 : n - 1]);
			if (item) location.href = item.href;
		}
	});
}
document.addEventListener('DOMContentLoaded', initShell);

/* ───────── type-specific object icons (12x12 stroke SVG) ───────── */
/* colored per type via the .tree-node .ic.t-<type> CSS rules */
const OBJ_PATHS = {
	domain:    '<circle cx="6" cy="6" r="4.5"/><ellipse cx="6" cy="6" rx="2.2" ry="4.5"/><line x1="1.5" y1="6" x2="10.5" y2="6"/>',
	ou:        '<path d="M1.3 3.5 L4.5 3.5 L5.3 4.8 L10.7 4.8 L10.7 9.5 L1.3 9.5 Z"/>',
	container: '<rect x="1.5" y="2.6" width="9" height="6.8" rx="0.4"/><line x1="1.5" y1="4.8" x2="10.5" y2="4.8"/>'
		+ '<circle cx="2.9" cy="3.7" r="0.5" fill="currentColor" stroke="none"/>'
		+ '<circle cx="4.2" cy="3.7" r="0.5" fill="currentColor" stroke="none"/>',
	user:      '<circle cx="6" cy="4" r="1.85"/><path d="M1.8 10.6 C2 8.1, 4 7.2, 6 7.2 C8 7.2, 10 8.1, 10.2 10.6"/>',
	computer:  '<rect x="1" y="2" width="10" height="6.4" rx="0.5"/><line x1="2.3" y1="3.3" x2="2.6" y2="3.3"/>'
		+ '<line x1="4" y1="10.4" x2="8" y2="10.4"/><line x1="6" y1="8.4" x2="6" y2="10.4"/>',
	group:     '<circle cx="3.8" cy="4.4" r="1.4"/><circle cx="8.2" cy="4.4" r="1.4"/>'
		+ '<path d="M0.8 9.8 C0.9 8.2, 2.2 7.5, 3.8 7.5 C4.8 7.5, 5.5 7.7, 6 8"/>'
		+ '<path d="M6 8 C6.5 7.7, 7.3 7.5, 8.2 7.5 C9.8 7.5, 11.1 8.2, 11.2 9.8"/>',
	host:      '<rect x="1.5" y="1.8" width="9" height="3.2" rx="0.4"/><rect x="1.5" y="6.4" width="9" height="3.2" rx="0.4"/>'
		+ '<circle cx="2.8" cy="3.4" r="0.45" fill="currentColor" stroke="none"/>'
		+ '<circle cx="2.8" cy="8.0" r="0.45" fill="currentColor" stroke="none"/>',
	zone:      '<circle cx="6" cy="6" r="4.5"/><line x1="1.5" y1="6" x2="10.5" y2="6"/><line x1="6" y1="1.5" x2="6" y2="10.5"/>',
	obj:       '<rect x="2" y="2" width="8" height="8" rx="0.8"/>'
};
function objIcon(type) {
	return '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" '
		+ 'stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round">'
		+ (OBJ_PATHS[type] || OBJ_PATHS.obj) + '</svg>';
}

/* ───────── right-click context menu ───────── */
/* items: {header,iconType,tag} | {section} | {divider} | {icon,label,onClick,danger,disabled,shortcut} */
function contextMenu(x, y, items) {
	$$('.ctx-menu').forEach(m => m.remove());
	const menu = h('div.ctx-menu', { style: { visibility: 'hidden' },
		oncontextmenu: e => e.preventDefault() });
	items.forEach(it => {
		if (it.divider) { menu.appendChild(h('div.ctx-div')); return; }
		if (it.section) { menu.appendChild(h('div.ctx-section', it.section)); return; }
		if (it.header) {
			menu.appendChild(h('div.ctx-header',
				h('span', { class: 't-' + (it.iconType || 'obj'), html: objIcon(it.iconType) }),
				h('span.name', it.header),
				it.tag ? h('span.tag', it.tag) : null));
			return;
		}
		const row = h('div', {
			class: 'ctx-item' + (it.danger ? ' danger' : '') + (it.disabled ? ' disabled' : '') },
			h('span.ctx-icon', it.icon || ''),
			h('span.ctx-label', it.label),
			it.shortcut ? h('span.ctx-shortcut', it.shortcut) : null);
		if (!it.disabled) row.onclick = () => { close(); if (it.onClick) it.onClick(); };
		menu.appendChild(row);
	});
	document.body.appendChild(menu);
	const r = menu.getBoundingClientRect();
	let nx = x, ny = y;
	if (x + r.width  > window.innerWidth  - 4) nx = window.innerWidth  - r.width  - 4;
	if (y + r.height > window.innerHeight - 4) ny = window.innerHeight - r.height - 4;
	menu.style.left = Math.max(4, nx) + 'px';
	menu.style.top  = Math.max(4, ny) + 'px';
	menu.style.visibility = 'visible';
	function close() {
		menu.remove();
		document.removeEventListener('mousedown', onAway, true);
		document.removeEventListener('contextmenu', onAway, true);
		document.removeEventListener('keydown', onKey, true);
	}
	function onAway(e) { if (!menu.contains(e.target)) close(); }
	function onKey(e) { if (e.key === 'Escape') close(); }
	setTimeout(() => {
		document.addEventListener('mousedown', onAway, true);
		document.addEventListener('contextmenu', onAway, true);
		document.addEventListener('keydown', onKey, true);
	}, 0);
	return close;
}

/* ───────── modal dialog ─────────
   opts: {cmd, subject, title, width, body, footer}
   returns { close, body, foot, setFooter } */
function modal(opts) {
	opts = opts || {};
	const bodyEl = h('div.modal-body');
	const footEl = h('div.modal-foot');
	const head = h('div.modal-head', opts.cmd
		? [h('span.title-cmd', opts.cmd),
		   opts.subject ? h('span.muted', '·') : null,
		   opts.subject ? h('span.title-obj', opts.subject) : null]
		: h('span', opts.title || ''));
	const closeBtn = h('button.modal-close', { title: 'close (Esc)' }, '✕');
	head.appendChild(closeBtn);
	const box = h('div.modal', { style: { width: (opts.width || 440) + 'px' } }, head, bodyEl, footEl);
	const backdrop = h('div.modal-backdrop', box);
	function close() { backdrop.remove(); document.removeEventListener('keydown', onKey, true); }
	function onKey(e) { if (e.key === 'Escape') close(); }
	closeBtn.onclick = close;
	backdrop.addEventListener('mousedown', e => { if (e.target === backdrop) close(); });
	document.addEventListener('keydown', onKey, true);
	if (opts.body) add(bodyEl, [opts.body]);
	function setFooter(nodes) { clear(footEl); add(footEl, [nodes]); }
	if (opts.footer) setFooter(opts.footer);
	document.body.appendChild(backdrop);
	const f = bodyEl.querySelector('input,select,textarea');
	if (f) f.focus();
	return { close: close, body: bodyEl, foot: footEl, setFooter: setFooter };
}

/* ───────── result modal ─────────
   Opens a modal, shows a spinner while `promise` resolves, then renders the
   returned entry array (each {attributes:{…}}) in a sortable grid with columns
   auto-derived from the attribute keys. Used by dedicated-endpoint actions. */
function showResultModal(title, subject, promise) {
	const host = h('div', { style: { minHeight: '120px' } }, h('div.empty', h('div.spinner.lg')));
	const m = modal({ cmd: title, subject: subject, width: 760, body: host });
	m.setFooter(btn('Close', null, m.close));
	Promise.resolve(promise).then(data => {
		clear(host);
		const list = Array.isArray(data) ? data : (data == null ? [] : [data]);
		if (!list.length) { host.appendChild(h('div.empty', 'no results')); return; }
		/* flatten attributes; collect column keys.
		   `attributes` is normally a dict, but some endpoints (e.g.
		   domainobjectacl) return it as an array of sub-records — expand
		   those into one grid row each. */
		const flatRows = [], keys = [];
		function pushRow(a) {
			const o = {};
			for (const k in a) {
				o[k] = Array.isArray(a[k]) ? a[k].map(fmtVal).join(', ') : fmtVal(a[k]);
				if (keys.indexOf(k) < 0) keys.push(k);
			}
			flatRows.push(o);
		}
		list.forEach(entry => {
			const a = (entry && entry.attributes) || entry || {};
			if (Array.isArray(a)) a.forEach(sub => pushRow(sub || {}));
			else pushRow(a);
		});
		if (!keys.length) { host.appendChild(h('div.empty', 'no results')); return; }
		const cols = keys.slice(0, 8).map(k => ({ key: k, label: k }));
		const g = grid(cols, { empty: 'no results' });
		host.style.maxHeight = '60vh';
		host.style.overflow = 'auto';
		host.appendChild(g.el);
		g.setData(flatRows);
	}).catch(e => {
		clear(host);
		host.appendChild(h('div.form-result.err', '[-] ' + (e && e.message ? e.message : String(e))));
	});
	return m;
}

/* A right-side detail/inspector pane that stays hidden until a row is
   selected and closes again on any click outside it. Closing it also clears
   the grid's row highlight. A click inside the linked grid is ignored — the
   row's own handler reopens the pane with the new selection.
   `gridGetter` returns the grid object (from grid()); Returns { el, show, hide }. */
function inspectorPane(label, subEl, body, gridGetter) {
	let pane;
	const hide = () => {
		pane.hidden = true;
		const g = gridGetter && gridGetter();
		if (g && g.setSelected) g.setSelected(null);   /* unhighlight the selected row */
	};
	const show = () => { pane.hidden = false; };
	pane = h('div.pane.right',
		h('div.pane-head', h('span', label), h('span.grow'), subEl || null,
			h('button.pane-close', { title: 'Close', onclick: hide }, '✕')),
		body);
	pane.hidden = true;
	document.addEventListener('mousedown', e => {
		if (pane.hidden || pane.contains(e.target)) return;
		const g = gridGetter && gridGetter();
		if (g && g.el && g.el.contains(e.target)) return;
		hide();
	});
	return { el: pane, show, hide };
}

/* ───────── exports ───────── */
window.PV = {
	h, add, $, $$, clear, api, toast, attr, fmtVal, uacFlags, objIcon,
	grid, tag, pageHead, searchField, btn, propRow, propGroup, propsView,
	withSpinner, runCmd, contextMenu, modal, showResultModal, inspectorPane,
	toggleLogPanel, panel: bottomPanel, cli, NAV, pages: {}
};
})();
