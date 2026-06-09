/* powerview.py web ui — Dashboard (domain summary + quick queries) */
(function () {
"use strict";
const { h, $, $$, add, clear, api, attr, uacFlags, tag, btn, toast } = window.PV;

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
function ago(iso) {
	const t = Date.parse(iso);
	if (isNaN(t)) return '';
	const s = Math.max(0, (Date.now() - t) / 1000);
	if (s < 60) return 'just now';
	if (s < 3600) return Math.floor(s / 60) + 'm ago';
	if (s < 86400) return Math.floor(s / 3600) + 'h ago';
	return Math.floor(s / 86400) + 'd ago';
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

const TIER0_GROUPS = ['Domain Admins', 'Enterprise Admins', 'Schema Admins',
	'Account Operators', 'Backup Operators'];

window.PV.pages.dashboard = function () {
	const main = $('#main');
	const dash = h('div.dash');
	main.append(
		h('div.page-head', h('span.title', 'Dashboard'), h('span.crumbs', '/ domain summary'),
			h('span.grow'), h('div.toolbar', btn('⟲ Re-scan', null, async () => {
				toast('info', 'rescanning findings…');
				try { await api.get('/api/findings?refresh=true'); } catch (e) {}
				window.PV.navigate('/dashboard', { replace: true });
			}))),
		dash);

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
	const bTier  = box(6, 'TIER-0 INVENTORY', '');
	const bSurf  = box(6, 'ATTACK SURFACE', 'live');
	const bOs    = box(6, 'OS BREAKDOWN', 'computer accounts');
	const bFindT = box(6, 'FINDINGS', 'by severity', true);
	const bAct   = box(6, 'RECENT ACTIVITY', 'session log');
	const bQuick = box(12, 'QUICK QUERIES', 'click to run in the CLI panel');

	function fill(body, nodes) { clear(body); body.classList.remove('empty'); add(body, [nodes]); }
	function fail(body, e) { fill(body, h('div.empty', (e && e.message) || 'unavailable')); }

	/* ─────────── quick queries (synchronous) ─────────── */
	fill(bQuick, h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '8px' } },
		QQ.map(def => h('div.qq-card', { onclick: () => window.PV.cli.run(def.cmd), title: def.cmd },
			h('span.dollar', '$'),
			h('span.cmd', def.cmd),
			def.page ? h('span.deep-hint', '↗ ' + (def.pageHint || def.page)) : null))));

	/* ─────────── fire every top-level fetch in parallel ─────────── */
	/* the USERS card fetch also carries pwdLastSet, so the krbtgt-age row of
	   the DOMAIN SNAPSHOT card reads from the same payload — no second call. */
	const usersP   = api.op('get', 'domainuser',
		{ args: { properties: ['sAMAccountName','adminCount','userAccountControl','pwdLastSet'] }, raw: true });
	const compsP   = api.op('get', 'domaincomputer',
		{ args: { properties: ['operatingSystem','userAccountControl','dnsHostName'] } });
	const groupsP  = api.get('/api/get/domaingroup');
	const findingsP = api.get('/api/findings');
	const logsP    = api.get('/api/logs?page=1&limit=12');
	const infoP    = api.get('/api/get/domaininfo');
	const siP      = api.get('/api/server/info');
	const dcsP     = api.get('/api/get/domaincontroller');
	const domP     = api.get('/api/get/domain');
	const trustsP  = api.get('/api/get/domaintrust');
	const enfP     = api.get('/api/server/ldap-enforcement');

	/* FSMO needs rootDn → starts once infoP resolves, but the 3 partition
	   queries themselves run as a Promise.all */
	const fsmoP = infoP.then(info => {
		const rootDn = info && info.root_dn;
		if (!rootDn) return { rootDn: null, domR: null, cfgR: null, schR: null };
		return Promise.all([
			api.op('get', 'domainobject',
				{ searchbase: rootDn, ldap_filter: '(fSMORoleOwner=*)', properties: ['fSMORoleOwner'] })
				.catch(() => null),
			api.op('get', 'domainobject',
				{ searchbase: 'CN=Configuration,' + rootDn, ldap_filter: '(fSMORoleOwner=*)',
				  properties: ['fSMORoleOwner', 'msDS-EnabledFeature'] }).catch(() => null),
			/* the Schema NC is a separate partition — read it directly */
			api.op('get', 'domainobject',
				{ searchbase: 'CN=Schema,CN=Configuration,' + rootDn, search_scope: 'BASE',
				  properties: ['fSMORoleOwner'] }).catch(() => null),
		]).then(([domR, cfgR, schR]) => ({ rootDn, domR, cfgR, schR }));
	}, () => ({ rootDn: null, domR: null, cfgR: null, schR: null }));

	/* TIER-0: all 5 group-member fetches in parallel */
	const tierP = Promise.all(TIER0_GROUPS.map(g =>
		api.op('get', 'domaingroupmember', { identity: g }).catch(() => null)));

	/* ─────────── consumers ─────────── */

	usersP.then(users => {
		if (!Array.isArray(users)) return fail(bUsers, new Error('unexpected response'));
		let adminCt = 0, disabled = 0;
		users.forEach(e => {
			const a = e.attributes || {};
			if (uacFlags(a.userAccountControl).includes('ACCOUNTDISABLE')) disabled++;
			if (String(attr(a, 'adminCount')) === '1') adminCt++;
		});
		fill(bUsers, kpi(users.length, null, null, adminCt + ' admins · ' + disabled + ' disabled'));
	}, e => fail(bUsers, e));

	compsP.then(comps => {
		if (!Array.isArray(comps)) { fail(bComp, new Error('unexpected response')); fail(bOs, new Error('unexpected response')); return; }
		const osMap = {};
		let servers = 0, workstations = 0;
		comps.forEach(e => {
			const os = attr(e.attributes || {}, 'operatingSystem') || 'Unknown';
			osMap[os] = (osMap[os] || 0) + 1;
			if (/server/i.test(os)) servers++;
			else if (os !== 'Unknown') workstations++;
		});
		fill(bComp, kpi(comps.length, null, null, workstations + ' workstations · ' + servers + ' servers'));
		const total = comps.length || 1;
		const bars = Object.entries(osMap).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([os, n]) =>
			bar(os, n / total * 100, n, /7|2008|2012|XP|Vista/.test(os) ? 'yellow' : ''));
		fill(bOs, bars.length ? bars : h('div.empty', 'no computers'));
	}, e => { fail(bComp, e); fail(bOs, e); });

	groupsP.then(groups => {
		if (!Array.isArray(groups)) return fail(bGroup, new Error('unexpected response'));
		fill(bGroup, kpi(groups.length, null, null, 'domain groups'));
	}, e => fail(bGroup, e));

	findingsP.then(data => {
		const findings = (data && data.findings) || [];
		const scanNote = bFindT.parentNode && bFindT.parentNode.querySelector('.card-head .mono');
		if (scanNote && data && data.generated_at) scanNote.textContent = 'scanned ' + ago(data.generated_at);
		const byId = {};
		findings.forEach(f => { byId[f.id] = f; });
		const cnt = id => (byId[id] && byId[id].count) || 0;

		const sevClass = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue' };
		const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
		const active = findings.filter(f => f.count > 0)
			.sort((a, b) => (sevOrder[a.severity] - sevOrder[b.severity]));
		const nBy = s => active.filter(f => f.severity === s).length;
		fill(bFind, kpi(nBy('critical') + nBy('high'), 'high', 'red',
			nBy('medium') + ' medium · ' + nBy('low') + ' low'));

		const findRows = active.length
			? active.map(f => h('tr',
				h('td', tag(f.severity.toUpperCase(), sevClass[f.severity] || 'blue')),
				h('td', { style: { color: 'var(--accent)' } }, f.code || f.id),
				h('td', f.subject || (f.count + ' ' + (f.unit || ''))),
				h('td', { style: { color: 'var(--text-2)', whiteSpace: 'normal', maxWidth: 'none' } },
					f.title || f.detail)))
			: [h('tr', h('td', { colspan: 4 }, h('div.empty', 'no findings')))];
		const stickyTh = w => {
			const s = { position: 'sticky', top: '0', background: 'var(--panel)', zIndex: 1 };
			if (w) s.width = w;
			return s;
		};
		fill(bFindT, h('div', { style: { maxHeight: '300px', overflowY: 'auto' } },
			h('table.grid',
				h('thead', h('tr', h('th', { style: stickyTh('70px') }, 'SEV'),
					h('th', { style: stickyTh('90px') }, 'ID'),
					h('th', { style: stickyTh('200px') }, 'SOURCE'),
					h('th', { style: stickyTh() }, 'DETAIL'))),
				h('tbody', findRows))));

		const sv = (label, id, kind) => {
			const n = cnt(id);
			return stat(label, n, n ? 'var(--' + kind + ')' : null);
		};
		fill(bSurf, h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '12px 18px' } },
			sv('SPN accounts', 'kerberoastable', 'yellow'),
			sv('AS-REP roastable', 'asrep-roastable', 'red'),
			sv('Unconstrained deleg', 'unconstrained-delegation', 'red'),
			sv('Pwd > 365d', 'stale-password', 'yellow'),
			sv('ESC templates', 'esc-vuln-template', 'red'),
			sv('Privileged (adminCount)', 'privileged-accounts', 'yellow')));
	}, e => { fail(bFind, e); fail(bFindT, e); fail(bSurf, e); });

	logsP.then(data => {
		const logs = ((data && data.logs) || []).slice().reverse();
		fill(bAct, logs.length ? logs.map(l => h('div.event-row',
			h('span.t', (l.timestamp || '').split(' ').pop().split(',')[0]),
			h('span.lvl', { style: { color: lvlColor(l.log_type) } }, lvlAbbr(l.log_type)),
			h('span.msg', l.debug_message || '')))
			: h('div.empty', 'no recent activity'));
	}, e => fail(bAct, e));

	/* ─────────── domain snapshot (one render once every source settles) ─────────── */
	(async () => {
		const FL = { '0': '2000', '1': '2003 interim', '2': '2003', '3': '2008',
			'4': '2008 R2', '5': '2012', '6': '2012 R2', '7': '2016 / 2019 / 2022',
			'10': '2025' };
		const fl = v => {
			v = Array.isArray(v) ? v[0] : v;
			return FL[String(v)] ? 'Windows Server ' + FL[String(v)] : (v == null ? '—' : String(v));
		};
		/* settle each promise to either its value or null so one failure
		   doesn't bring down the whole card */
		const settle = p => p.then(v => v, () => null);
		const [info, si, dcs, dom, users, trusts, enf, fsmo] = await Promise.all(
			[infoP, siP, dcsP, domP, usersP, trustsP, enfP, fsmoP].map(settle));

		const rows = [];
		const raw = (si && si.raw) || {};
		if (Object.keys(raw).length) {
			rows.push(['Domain functional level', fl(raw.domainFunctionality), '']);
			rows.push(['Forest functional level', fl(raw.forestFunctionality), '']);
			rows.push(['DC functional level', fl(raw.domainControllerFunctionality), '']);
		}
		if (Array.isArray(dcs)) {
			const names = dcs.map(e => {
				const a = e.attributes || {};
				return attr(a, 'dNSHostName') || attr(a, 'name') || attr(a, 'cn') || '';
			}).filter(Boolean).map(n => n.split('.')[0]);
			rows.push(['Domain controllers',
				names.length + (names.length ? '  (' + names.join(', ') + ')' : ''), '']);
		}
		if (fsmo && fsmo.rootDn) {
			const owners = [];
			(Array.isArray(fsmo.domR) ? fsmo.domR : []).forEach(e => {
				const o = e.attributes && attr(e.attributes, 'fSMORoleOwner');
				if (o) owners.push(o);
			});
			let rbList = [];
			(Array.isArray(fsmo.cfgR) ? fsmo.cfgR : []).forEach(e => {
				const a = e.attributes || {};
				const o = attr(a, 'fSMORoleOwner');
				if (o) owners.push(o);
				const ef = a['msDS-EnabledFeature'];
				if (ef) rbList = rbList.concat(Array.isArray(ef) ? ef : [ef]);
			});
			(Array.isArray(fsmo.schR) ? fsmo.schR : []).forEach(e => {
				const o = e.attributes && attr(e.attributes, 'fSMORoleOwner');
				if (o) owners.push(o);
			});
			if (owners.length) {
				const counts = {};
				owners.forEach(dn => {
					const m = String(dn).match(/CN=NTDS Settings,CN=([^,]+)/i);
					const d = m ? m[1] : '?';
					counts[d] = (counts[d] || 0) + 1;
				});
				const dcNames = Object.keys(counts);
				rows.push(['FSMO holders', dcNames.length === 1
					? dcNames[0] + ' (all ' + owners.length + ' roles)'
					: dcNames.map(d => d + ' (' + counts[d] + ')').join(', '), '']);
			}
			if (fsmo.cfgR != null) {
				const rbOn = rbList.some(v => /recycle bin/i.test(String(v)));
				rows.push(['AD Recycle Bin', rbOn ? 'Enabled' : 'Disabled', rbOn ? 'g' : 'y']);
			}
		}
		if (dom) {
			const de = Array.isArray(dom) ? dom[0] : dom;
			const da = (de && de.attributes) || {};
			const maq = attr(da, 'ms-DS-MachineAccountQuota');
			if (maq != null && maq !== '')
				rows.push(['MAQ', String(maq), String(maq) === '0' ? 'g' : 'y']);
			const lt = attr(da, 'lockoutThreshold');
			if (lt != null && lt !== '') {
				const n = parseInt(lt, 10);
				rows.push(['Account lockout threshold',
					n === 0 ? 'Disabled (0)' : n + ' attempts',
					n === 0 ? 'r' : 'g']);
			}
		}
		/* krbtgt password age — pulled from the shared USERS payload */
		if (Array.isArray(users)) {
			const kt = users.find(e => {
				const a = e.attributes || {};
				return String(attr(a, 'sAMAccountName')).toLowerCase() === 'krbtgt';
			});
			const t = kt && Date.parse(attr(kt.attributes || {}, 'pwdLastSet'));
			if (t && !isNaN(t)) {
				const d = Math.floor((Date.now() - t) / 864e5);
				rows.push(['krbtgt password age', d + ' days' + (d > 180 ? '   ⚠ rotate' : ''),
					d > 180 ? 'r' : 'g']);
			}
		}
		if (Array.isArray(trusts)) {
			const n = trusts.length;
			rows.push(['Trusts', n ? String(n) : 'none', n ? 'y' : 'g']);
		}
		if (enf) {
			if (enf.signing == null && enf.channel_binding == null) {
				rows.push(['LDAP enforcement', 'could not probe (Kerberos auth)', 'y']);
			} else {
				const mark = v => v == null ? ['(could not probe)', 'y']
					: v ? ['Required', 'g'] : ['Not required', 'r'];
				const s = mark(enf.signing), c = mark(enf.channel_binding);
				rows.push(['LDAP signing required', s[0], s[1]]);
				rows.push(['Channel binding', c[0], c[1]]);
			}
		}

		const note = bSnap.parentNode && bSnap.parentNode.querySelector('.card-head .mono');
		if (note) note.textContent = (info && info.domain) || '';
		fill(bSnap, rows.length
			? h('div.snapshot-grid', rows.map(r => h('div.snapshot-row',
				h('span.k', r[0]), h('span', { class: 'v ' + (r[2] || '') }, r[1]))))
			: h('div.empty', 'snapshot unavailable'));
	})();

	/* ─────────── tier-0 inventory (5 parallel fetches) ─────────── */
	tierP.then(results => {
		const strip = h('div.member-strip');
		let any = false;
		TIER0_GROUPS.forEach((gname, i) => {
			const data = results[i];
			if (data == null) return;
			const members = (Array.isArray(data) ? data : []).map(e => {
				const a = e.attributes || {};
				return attr(a, 'MemberName') || attr(a, 'MemberSID') || '';
			}).filter(Boolean);
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
		});
		fill(bTier, any ? strip : h('div.empty', 'no tier-0 groups resolved'));
	});

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
