/* powerview.py web ui — Dashboard (domain summary + quick-query results drawer) */
(function () {
"use strict";
const { h, $, $$, add, clear, api, attr, fmtVal, uacFlags, tag, btn, toast } = window.PV;

function kpi(value, delta, deltaCls, sub) {
	return [h('div.kpi', String(value), delta ? h('span', { class: 'delta ' + (deltaCls || '') }, delta) : null),
		h('div.kpi-sub', sub || '')];
}
function stat(label, n, color) {
	return h('div', h('div.mono', { style: { fontSize: '24px', fontWeight: 600, color: color || 'var(--text)' } }, String(n)),
		h('div.mono.xs.muted', { style: { textTransform: 'uppercase', letterSpacing: '.04em' } }, label));
}
function bar(label, pct, n, cls) {
	return h('div.bar', h('span.lbl', label),
		h('span.track', h('span', { class: 'fill ' + (cls || ''), style: { width: pct + '%' } })),
		h('span.val', n != null ? String(n) : Math.round(pct) + '%'));
}

/* ── quick-query catalog: real PowerView commands + deep-link target ── */
const QQ = [
	{ cmd: 'Get-DomainUser -SPN', page: 'users', pageHint: 'Users' },
	{ cmd: 'Get-DomainUser -PreauthNotRequired', page: 'users', pageHint: 'Users',
	  finding: 'AS-REP roastable accounts — request an encrypted timestamp from the KDC and crack it offline.' },
	{ cmd: 'Get-DomainComputer -Unconstrained', page: 'computers', pageHint: 'Computers',
	  finding: 'Unconstrained delegation — compromising the host yields any forwarded TGT, including DC$.' },
	{ cmd: 'Get-DomainObjectAcl -Identity "Domain Admins"', page: null },
	{ cmd: 'Get-DomainController', page: 'computers', pageHint: 'Computers' },
	{ cmd: 'Get-DomainGPO', page: 'gpos', pageHint: 'GPOs' },
	{ cmd: 'Get-DomainOU', page: 'ous', pageHint: 'OUs' },
	{ cmd: 'Get-DomainTrust', page: null },
	{ cmd: 'Get-DomainCATemplate', page: 'ca', pageHint: 'CA' },
	{ cmd: 'Get-DomainComputer -LAPS', page: 'computers', pageHint: 'Computers' },
	{ cmd: 'Get-DomainGroup -AdminCount', page: 'groups', pageHint: 'Groups' },
	{ cmd: 'Get-DomainDNSZone', page: 'dns', pageHint: 'DNS' }
];
const PAGE_HREF = { users: '/users', computers: '/computers', groups: '/groups',
	dns: '/dns', ca: '/ca', ous: '/ou', gpos: '/gpo' };
const RISKY = /TRUSTED_FOR_DELEGATION|DONT_REQ_PREAUTH|DONT_REQUIRE_PREAUTH|WriteDacl|GenericAll|WriteOwner|AllExtendedRights|ACCOUNTDISABLE|PASSWD_NOTREQD|cpassword/i;

/* turn an /api/execute result into {cols, rows} for the drawer table */
function toTable(out) {
	if (!Array.isArray(out)) return { cols: ['result'], rows: [[fmtVal(out)]] };
	/* some commands (e.g. Get-DomainObjectAcl) wrap rows in entries whose
	   `attributes` is itself an array of objects — flatten those to real rows */
	if (out.length && out.every(e => e && typeof e === 'object' && Array.isArray(e.attributes)))
		out = out.reduce((acc, e) => acc.concat(e.attributes), []);
	if (!out.length) return { cols: [], rows: [] };
	const entryMode = out[0] && typeof out[0] === 'object' && out[0].attributes
		&& !Array.isArray(out[0].attributes);
	const objOf = e => entryMode ? (e.attributes || {}) : e;
	if (out[0] && typeof out[0] === 'object') {
		const cols = [];
		out.slice(0, 50).forEach(e => Object.keys(objOf(e) || {}).forEach(k => {
			if (cols.indexOf(k) < 0) cols.push(k);
		}));
		const use = cols.slice(0, 8);
		return {
			cols: use,
			rows: out.map(e => { const o = objOf(e) || {}; return use.map(k => fmtVal(o[k])); })
		};
	}
	return { cols: ['value'], rows: out.map(x => [fmtVal(x)]) };
}

window.PV.pages.dashboard = function () {
	const main = $('#main');
	const dash = h('div.dash');
	const drawerEl = h('div.results-drawer');
	drawerEl.hidden = true;
	main.append(
		h('div.page-head', h('span.title', 'Dashboard'), h('span.crumbs', '/ domain summary'),
			h('span.grow'), h('div.toolbar', btn('⟲ Re-scan', null, () => location.reload()))),
		dash, drawerEl);

	function box(span, title, note, flush) {
		const body = h('div', { class: 'card-body' + (flush ? ' flush' : '') },
			h('div.empty', h('div.spinner')));
		dash.appendChild(h('div', { class: 'card span-' + span },
			h('div.card-head', h('span.title', title), h('span.grow'), note ? h('span.mono.xs.muted', note) : null),
			body));
		return body;
	}
	const bUsers = box(3, 'USERS', 'CN=Users');
	const bComp  = box(3, 'COMPUTERS', 'all OUs');
	const bGroup = box(3, 'GROUPS', '');
	const bFind  = box(3, 'FINDINGS', 'action needed');
	const bSnap  = box(6, 'DOMAIN SNAPSHOT', '…');
	const bTier  = box(6, 'TIER-0 INVENTORY', 'protected by AdminSDHolder');
	const bSurf  = box(6, 'ATTACK SURFACE', 'live');
	const bOs    = box(6, 'OS BREAKDOWN', 'computer accounts');
	const bFindT = box(6, 'FINDINGS', 'by severity', true);
	const bAct   = box(6, 'RECENT ACTIVITY', 'session log');
	const bQuick = box(12, 'QUICK QUERIES', 'click to run · results dock below');

	function fill(body, nodes) { clear(body); body.classList.remove('empty'); add(body, [nodes]); }

	/* ─────────────── quick queries + results drawer ─────────────── */
	let results = [], activeId = null, drawerH = 310, drag = null;
	let connTarget = '';
	api.get('/api/connectioninfo').then(c => {
		connTarget = (c.protocol || 'ldap').toLowerCase() + '://' + (c.ldap_address || '');
	}).catch(() => {});

	const qqCards = {};
	fill(bQuick, h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '8px' } },
		QQ.map(def => {
			const card = h('div.qq-card', { onclick: () => openQuery(def), title: def.cmd },
				h('span.dollar', '$'),
				h('span.cmd', def.cmd),
				def.page ? h('span.deep-hint', '↗ ' + (def.pageHint || def.page)) : null);
			qqCards[def.cmd] = card;
			return card;
		})));

	function refreshCards() {
		QQ.forEach(def => {
			const open = results.some(r => r.id === def.cmd);
			qqCards[def.cmd].classList.toggle('open', open);
		});
	}

	async function openQuery(def) {
		const id = def.cmd;
		if (!results.find(r => r.id === id)) {
			const rec = { id: id, def: def, running: true, cols: [], rows: [], error: null, tookMs: 0 };
			results.push(rec);
			activeId = id;
			redrawDrawer();
			const t0 = performance.now();
			try {
				const res = await api.execute(def.cmd);
				const tbl = toTable(res && res.result);
				rec.cols = tbl.cols; rec.rows = tbl.rows;
			} catch (e) { rec.error = e.message; }
			rec.tookMs = Math.round(performance.now() - t0);
			rec.running = false;
		} else {
			activeId = id;
		}
		redrawDrawer();
	}
	function closeQuery(id) {
		results = results.filter(r => r.id !== id);
		if (activeId === id) activeId = results.length ? results[results.length - 1].id : null;
		redrawDrawer();
	}
	function closeAll() { results = []; activeId = null; redrawDrawer(); }

	function copyJson(rec) {
		const out = rec.rows.map(row => {
			const o = {}; rec.cols.forEach((c, i) => o[c] = row[i]); return o;
		});
		try {
			navigator.clipboard.writeText(JSON.stringify(out, null, 2));
			toast('success', 'copied ' + rec.rows.length + ' row(s) as JSON');
		} catch (e) { toast('error', 'clipboard unavailable'); }
	}

	function resultTable(rec) {
		return h('table.grid',
			h('thead', h('tr', rec.cols.map(c => h('th', c)))),
			h('tbody', rec.rows.map(row => h('tr', row.map((v, i) =>
				h('td', { style: { color: RISKY.test(v) ? 'var(--red)' : i === 0 ? 'var(--accent)' : 'var(--text)' } },
					String(v)))))));
	}
	function renderResult(rec) {
		const q = rec.def;
		const meta = rec.running
			? h('span.drawer-meta', h('span.drawer-spinner'), '  executing…')
			: rec.error
				? h('span.drawer-meta', { style: { color: 'var(--red)' } }, 'failed')
				: h('span.drawer-meta', h('span.num', String(rec.rows.length)), ' rows · ',
					h('span.num', String(rec.tookMs)), 'ms' + (connTarget ? '  ·  ' + connTarget : ''));
		const cmdbar = h('div.drawer-cmdbar',
			h('span.drawer-cmd', h('span.prompt', 'PV ›'), q.cmd),
			meta,
			h('div.drawer-actions',
				q.page ? h('button.drawer-action.deep',
					{ title: 'Open in the ' + (q.pageHint || q.page) + ' page', onclick: () => { location.href = PAGE_HREF[q.page]; } },
					'↗ Open in ' + (q.pageHint || q.page)) : null,
				h('button.drawer-action', { title: 'Open the log panel',
					onclick: () => { if (window.PV.toggleLogPanel) window.PV.toggleLogPanel(true); } }, '>_ Logs'),
				h('button.drawer-action', { title: 'Copy result as JSON', onclick: () => copyJson(rec) }, '⧉ Copy JSON')));
		const nodes = [cmdbar];
		if (q.finding && !rec.running && !rec.error)
			nodes.push(h('div.drawer-finding', h('span.icn', '⚠'), h('span', q.finding)));
		let body;
		if (rec.running)
			body = h('div.drawer-body', h('div.drawer-running', h('span.drawer-spinner'),
				h('span', 'executing ' + q.cmd + ' …')));
		else if (rec.error)
			body = h('div.drawer-body', h('div.drawer-empty', { style: { color: 'var(--red)' } }, rec.error));
		else if (!rec.rows.length)
			body = h('div.drawer-body', h('div.drawer-empty', 'no results'));
		else
			body = h('div.drawer-body', resultTable(rec));
		nodes.push(body);
		return nodes;
	}
	function redrawDrawer() {
		refreshCards();
		if (!results.length) { drawerEl.hidden = true; return; }
		drawerEl.hidden = false;
		drawerEl.style.height = drawerH + 'px';
		clear(drawerEl);
		const resize = h('div.drawer-resize', { title: 'drag to resize' });
		resize.addEventListener('mousedown', e => { drag = { y: e.clientY, h: drawerH }; e.preventDefault(); });
		const tabs = h('div.drawer-tabs',
			results.map(r => h('div', { class: 'drawer-tab' + (r.id === activeId ? ' active' : ''),
				onclick: () => { activeId = r.id; redrawDrawer(); } },
				h('span.dollar', { style: { color: 'var(--accent)' } }, '$'),
				h('span', r.def.cmd),
				h('span.count', r.running ? '…' : '·' + r.rows.length),
				h('button.x', { title: 'close tab',
					onclick: e => { e.stopPropagation(); closeQuery(r.id); } }, '✕'))),
			h('button.drawer-closeall', { title: 'close all', onclick: closeAll }, 'Close all'));
		drawerEl.append(resize, tabs);
		const rec = results.find(r => r.id === activeId);
		if (rec) add(drawerEl, renderResult(rec));
	}
	window.addEventListener('mousemove', e => {
		if (!drag) return;
		drawerH = Math.max(120, Math.min(700, drag.h + (drag.y - e.clientY)));
		drawerEl.style.height = drawerH + 'px';
	});
	window.addEventListener('mouseup', () => { drag = null; });

	/* ─────────────── domain summary cards ─────────────── */
	async function safe(fn, body) {
		try { return await fn(); }
		catch (e) { if (body) fill(body, h('div.empty', e.message)); return null; }
	}

	(async () => {
		const users = await safe(() => api.op('get', 'domainuser',
			{ args: { properties: ['sAMAccountName','adminCount','userAccountControl','servicePrincipalName','pwdLastSet'] } }), bUsers);
		let spnCt = 0, asrep = 0, adminCt = 0, disabled = 0, stale = 0;
		if (users) {
			users.forEach(e => {
				const a = e.attributes || {};
				if (a.servicePrincipalName) spnCt++;
				const fl = uacFlags(a.userAccountControl);
				if (fl.includes('DONT_REQ_PREAUTH')) asrep++;
				if (fl.includes('ACCOUNTDISABLE')) disabled++;
				if (String(attr(a, 'adminCount')) === '1') adminCt++;
				const t = Date.parse(attr(a, 'pwdLastSet'));
				if (!isNaN(t) && (Date.now() - t) / 864e5 > 365) stale++;
			});
			fill(bUsers, kpi(users.length, null, null, adminCt + ' admins · ' + disabled + ' disabled'));
		}
		const comps = await safe(() => api.op('get', 'domaincomputer',
			{ args: { properties: ['operatingSystem','userAccountControl','dnsHostName'] } }), bComp);
		let unconstrained = 0;
		const osMap = {};
		if (comps) {
			comps.forEach(e => {
				const a = e.attributes || {};
				const fl = uacFlags(a.userAccountControl);
				if (fl.includes('TRUSTED_FOR_DELEGATION')) unconstrained++;
				const os = attr(a, 'operatingSystem') || 'Unknown';
				osMap[os] = (osMap[os] || 0) + 1;
			});
			fill(bComp, kpi(comps.length, null, null, Object.keys(osMap).length + ' distinct OS versions'));
			const total = comps.length || 1;
			const bars = Object.entries(osMap).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([os, n]) =>
				bar(os, n / total * 100, n, /7|2008|2012|XP|Vista/.test(os) ? 'yellow' : ''));
			fill(bOs, bars.length ? bars : h('div.empty', 'no computers'));
		}
		const groups = await safe(() => api.get('/api/get/domaingroup'), bGroup);
		if (groups) fill(bGroup, kpi(groups.length, null, null, 'domain groups'));

		let escCt = 0;
		const tmpls = await safe(() => api.op('get', 'domaincatemplate', { resolve_sids: true }));
		if (tmpls) tmpls.forEach(e => { const a = e.attributes || {};
			if (a.Vulnerable || a.vulnerable || a['Enrollee Supplies Subject']) escCt++; });

		const F = [];
		if (escCt) F.push(['high', 'ESC', escCt + ' template(s)', 'Vulnerable ADCS certificate templates detected']);
		if (asrep) F.push(['high', 'ASREP', asrep + ' account(s)', 'DONT_REQ_PREAUTH set — AS-REP roastable']);
		if (unconstrained) F.push(['high', 'UNCDEL', unconstrained + ' host(s)', 'Trusted for unconstrained delegation']);
		if (spnCt) F.push(['med', 'KERB', spnCt + ' account(s)', 'servicePrincipalName set — Kerberoastable']);
		if (stale) F.push(['med', 'STALE', stale + ' account(s)', 'Password not changed in > 365 days']);
		if (adminCt) F.push(['low', 'ADMIN', adminCt + ' account(s)', 'adminCount=1 — protected / privileged']);
		const sev = { high: 'red', med: 'yellow', low: 'blue' };
		fill(bFind, kpi(F.filter(f => f[0] === 'high').length, 'high', 'red',
			F.filter(f => f[0] === 'med').length + ' medium · ' + F.filter(f => f[0] === 'low').length + ' low'));
		const findRows = F.length
			? F.map(f => h('tr',
				h('td', tag(f[0].toUpperCase(), sev[f[0]])),
				h('td', { style: { color: 'var(--accent)' } }, f[1]),
				h('td', f[2]),
				h('td', { style: { color: 'var(--text-2)', whiteSpace: 'normal', maxWidth: 'none' } }, f[3])))
			: [h('tr', h('td', { colspan: 4 }, h('div.empty', 'no findings')))];
		fill(bFindT, h('table.grid',
			h('thead', h('tr', h('th', { style: { width: '60px' } }, 'SEV'),
				h('th', { style: { width: '90px' } }, 'ID'),
				h('th', { style: { width: '200px' } }, 'SOURCE'), h('th', 'DETAIL'))),
			h('tbody', findRows)));

		fill(bSurf, h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '12px 18px' } },
			stat('SPN accounts', spnCt, spnCt ? 'var(--yellow)' : null),
			stat('AS-REP roastable', asrep, asrep ? 'var(--red)' : null),
			stat('Unconstrained deleg', unconstrained, unconstrained ? 'var(--red)' : null),
			stat('Pwd > 365d', stale, stale ? 'var(--yellow)' : null),
			stat('ESC templates', escCt, escCt ? 'var(--red)' : null),
			stat('Privileged (adminCount)', adminCt, adminCt ? 'var(--yellow)' : null)));
	})();

	(async () => {
		try {
			const data = await api.get('/api/logs?page=1&limit=12');
			const logs = (data.logs || []).slice().reverse();
			/* 3 columns, no header: timestamp · [LEVEL] · message */
			fill(bAct, logs.length ? logs.map(l => h('div.event-row',
				h('span.t', (l.timestamp || '').split(' ').pop().split(',')[0]),
				h('span.lvl', { style: { color: lvlColor(l.log_type) } }, lvlAbbr(l.log_type)),
				h('span.msg', l.debug_message || '')))
				: h('div.empty', 'no recent activity'));
		} catch (e) { fill(bAct, h('div.empty', e.message)); }
	})();

	/* ─────────────── domain snapshot ─────────────── */
	(async () => {
		const FL = { '0': '2000', '1': '2003 interim', '2': '2003', '3': '2008',
			'4': '2008 R2', '5': '2012', '6': '2012 R2', '7': '2016 / 2019 / 2022',
			'10': '2025' };
		const fl = v => {
			v = Array.isArray(v) ? v[0] : v;
			return FL[String(v)] ? 'Windows Server ' + FL[String(v)] : (v == null ? '—' : String(v));
		};
		const rows = [];
		try {
			const si = await api.get('/api/server/info');
			const raw = (si && si.raw) || {};
			rows.push(['Domain functional level', fl(raw.domainFunctionality), '']);
			rows.push(['Forest functional level', fl(raw.forestFunctionality), '']);
			rows.push(['DC functional level', fl(raw.domainControllerFunctionality), '']);
		} catch (e) {}
		try {
			const dcs = await api.get('/api/get/domaincontroller');
			const names = (Array.isArray(dcs) ? dcs : []).map(e => {
				const a = e.attributes || {};
				return attr(a, 'dNSHostName') || attr(a, 'name') || attr(a, 'cn') || '';
			}).filter(Boolean).map(n => n.split('.')[0]);
			rows.push(['Domain controllers',
				names.length + (names.length ? '  (' + names.join(', ') + ')' : ''), '']);
		} catch (e) {}
		try {
			const info = await api.get('/api/get/domaininfo');
			if (info && info.root_dn) {
				const dobj = await api.op('get', 'domainobject',
					{ identity: info.root_dn, properties: ['ms-DS-MachineAccountQuota'] });
				const da = Array.isArray(dobj) ? dobj[0] : dobj;
				const maq = da && da.attributes && attr(da.attributes, 'ms-DS-MachineAccountQuota');
				if (maq != null && maq !== '')
					rows.push(['MachineAccountQuota', String(maq), String(maq) === '0' ? 'g' : 'y']);
			}
		} catch (e) {}
		try {
			const kt = await api.op('get', 'domainuser', { identity: 'krbtgt', properties: ['pwdLastSet'], raw: true });
			const ka = Array.isArray(kt) ? kt[0] : kt;
			const t = Date.parse(ka && ka.attributes && attr(ka.attributes, 'pwdLastSet'));
			if (!isNaN(t)) {
				const d = Math.floor((Date.now() - t) / 864e5);
				rows.push(['krbtgt password age', d + ' days' + (d > 180 ? '   ⚠ rotate' : ''),
					d > 180 ? 'r' : 'g']);
			}
		} catch (e) {}
		try {
			const trusts = await api.get('/api/get/domaintrust');
			const n = Array.isArray(trusts) ? trusts.length : 0;
			rows.push(['Trusts', n ? String(n) : 'none', n ? 'y' : 'g']);
		} catch (e) {}

		const note = bSnap.parentNode && bSnap.parentNode.querySelector('.card-head .mono');
		if (note) {
			try { note.textContent = (await api.get('/api/connectioninfo')).domain || ''; }
			catch (e) { note.textContent = ''; }
		}
		fill(bSnap, rows.length
			? h('div.snapshot-grid', rows.map(r => h('div.snapshot-row',
				h('span.k', r[0]), h('span', { class: 'v ' + (r[2] || '') }, r[1]))))
			: h('div.empty', 'snapshot unavailable'));
	})();

	/* ─────────────── tier-0 inventory ─────────────── */
	(async () => {
		const GROUPS = ['Domain Admins', 'Enterprise Admins', 'Schema Admins',
			'Account Operators', 'Backup Operators'];
		const strip = h('div.member-strip');
		let any = false;
		for (const gname of GROUPS) {
			let members;
			try {
				const data = await api.op('get', 'domaingroupmember', { identity: gname });
				members = (Array.isArray(data) ? data : []).map(e => {
					const a = e.attributes || {};
					return attr(a, 'MemberName') || attr(a, 'MemberSID') || '';
				}).filter(Boolean);
			} catch (e) { continue; }
			any = true;
			strip.appendChild(h('div.member-group',
				h('div.gname',
					h('div.nm', gname),
					h('div.sub', members.length + ' member' + (members.length === 1 ? '' : 's'))),
				h('div.avatars', members.length
					? members.map(m => {
						const low = m.toLowerCase();
						const isSvc = /^svc[._-]/.test(low) || low.indexOf('backup') > -1 || m.endsWith('$');
						const isAdmin = low === 'administrator';
						const ini = (m.replace(/\$$/, '').split(/[._\- ]/).map(s => s[0])
							.filter(Boolean).slice(0, 2).join('') || m.slice(0, 2)).toUpperCase();
						return h('span', { class: 'avatar-pill' + (isSvc ? ' svc' : '') + (isAdmin ? ' admin' : '') },
							h('span.av', ini), m);
					})
					: h('span.muted.mono.xs', '— no members resolved'))));
		}
		fill(bTier, any ? strip : h('div.empty', 'no tier-0 groups resolved'));
	})();

	function lvlColor(t) {
		t = (t || '').toUpperCase();
		return t === 'ERROR' || t === 'CRITICAL' ? 'var(--red)' : t === 'WARNING' ? 'var(--yellow)'
			: t === 'DEBUG' ? 'var(--muted)' : t === 'SUCCESS' ? 'var(--accent)' : 'var(--blue)';
	}
	function lvlAbbr(t) {
		t = (t || '').toUpperCase();
		return { WARNING: 'WARN', ERROR: 'ERR', SUCCESS: 'OK' }[t] || t || 'INFO';
	}
};
})();
