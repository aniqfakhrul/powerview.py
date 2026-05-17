/* powerview.py web ui — ops pages: SMB, Utils, Logs, Settings */
(function () {
"use strict";
const { h, $, $$, clear, api, objIcon, grid, tag, btn, toast, runCmd, withSpinner } = window.PV;

/* ============================ SMB BROWSER ============================ */
window.PV.pages.smb = function () {
	const main = $('#main');
	const hostsEl = h('div.tree');
	const hostShares = {};
	const filesHost = h('div.table-wrap');
	const crumb = h('span.crumbs');
	const filesHead = h('div.pane-head', h('span', 'Files'));
	let curHost = null, curShare = null, curPath = '';
	const hosts = [];

	/* ── alternate-credentials bar ── */
	const AUTH_LABEL = { password: 'Password', hash: 'NT Hash (PtH)', aes: 'AES Key', ccache: 'Ticket (PtT)' };
	const SECRET_PREFIX = { password: 'PWD', hash: 'NTLM', aes: 'KEY', ccache: 'TKT' };
	const SECRET_PH = { password: '••••••••', hash: 'aad3b435…:31d6cfe0…',
		aes: 'AES key (32 or 64 hex)', ccache: '(loaded from ccache path)' };
	let credMode = 'session';                          /* 'session' | 'alt' */
	const cred = { domain: '', username: '', authType: 'password', secret: '', ccachePath: '' };
	let authStatus = { kind: 'session', msg: 'bound session credentials' };
	const credBar = h('div.cred-bar');

	function getCreds() {
		if (credMode === 'session') return {};
		const c = {};
		if (cred.domain.trim()) c.domain = cred.domain.trim();
		if (cred.username.trim()) c.username = cred.username.trim();
		const s = cred.secret.trim();
		if (cred.authType === 'password' && s) c.password = s;
		else if (cred.authType === 'hash' && s) {
			if (s.indexOf(':') > -1) { const p = s.split(':'); c.lmhash = p[0]; c.nthash = p[1]; }
			else c.nthash = s;
		} else if (cred.authType === 'aes' && s) c.aesKey = s;
		else if (cred.authType === 'ccache' && cred.ccachePath.trim()) c.ccache = cred.ccachePath.trim();
		return c;
	}
	function validateCreds() {
		if (credMode === 'session') return null;
		if (!cred.username.trim()) return { warn: false, msg: 'username required' };
		if (cred.authType === 'ccache' && !cred.ccachePath.trim())
			return { warn: false, msg: 'ccache path required' };
		if (cred.authType !== 'ccache' && !cred.secret.trim())
			return { warn: false, msg: AUTH_LABEL[cred.authType] + ' required' };
		const s = cred.secret.trim();
		if (cred.authType === 'hash') {
			const nt = s.indexOf(':') > -1 ? s.split(':').pop() : s;
			if (!/^[0-9a-f]{32}$/i.test(nt)) return { warn: true, msg: 'NT hash should be 32 hex chars' };
		}
		if (cred.authType === 'aes' && !/^([0-9a-f]{32}|[0-9a-f]{64})$/i.test(s))
			return { warn: true, msg: 'AES key should be 32 or 64 hex chars' };
		return null;
	}
	function credField(width, prefix, control, extra) {
		return h('div', { class: 'cred-field' + (credMode === 'alt' ? '' : ' dim'),
			style: Object.assign({ width: width + 'px' }, extra || {}) },
			h('span.prefix', prefix), control);
	}
	function renderCredBar() {
		clear(credBar);
		const alt = credMode === 'alt';
		const seg = h('div.seg',
			h('button', { class: credMode === 'session' ? 'active' : '',
				onclick: () => { credMode = 'session';
					authStatus = { kind: 'session', msg: 'bound session credentials' }; renderCredBar(); } }, 'Session'),
			h('button', { class: alt ? 'active' : '',
				onclick: () => { credMode = 'alt';
					authStatus = { kind: 'warn', msg: 'alternate creds — not tested' }; renderCredBar(); } }, 'Alternate'));

		const domIn = h('input', { value: cred.domain, placeholder: 'domain', disabled: !alt,
			spellcheck: 'false', oninput: e => cred.domain = e.target.value });
		const userIn = h('input', { value: cred.username, placeholder: 'sAMAccountName', disabled: !alt,
			spellcheck: 'false', oninput: e => cred.username = e.target.value });
		const authSel = h('select', { disabled: !alt,
			onchange: e => { cred.authType = e.target.value; cred.secret = ''; renderCredBar(); } },
			['password', 'hash', 'aes', 'ccache'].map(t => h('option', { value: t }, AUTH_LABEL[t])));
		authSel.value = cred.authType;
		const secretIn = h('input', {
			type: cred.authType === 'password' ? 'password' : 'text',
			value: cred.secret, placeholder: SECRET_PH[cred.authType],
			disabled: !alt || cred.authType === 'ccache',
			spellcheck: 'false', autocomplete: 'off',
			oninput: e => cred.secret = e.target.value });
		const pathIn = h('input', { value: cred.ccachePath, placeholder: '/tmp/krb5cc_…',
			disabled: !alt, spellcheck: 'false', oninput: e => cred.ccachePath = e.target.value });

		const k = authStatus.kind;
		const pill = h('span', { class: 'test-pill ' + (k === 'ok' ? 'ok' : k === 'err' ? 'err' : k === 'warn' ? 'warn' : '') },
			k === 'testing' ? h('span.drawer-spinner', { style: { width: '8px', height: '8px' } })
				: (/^(ok|err|warn)$/.test(k) ? '● ' : '◌ '),
			authStatus.msg);
		const testBtn = btn(k === 'testing' ? 'Testing…' : 'Test', null, runTest);
		if (k === 'testing') testBtn.disabled = true;

		credBar.append(
			h('span.lbl', 'Auth'), seg,
			credField(118, 'DOM', domIn),
			credField(170, 'USER', userIn),
			credField(120, 'AUTH', authSel),
			credField(240, SECRET_PREFIX[cred.authType], secretIn, { flex: '1 1 200px', minWidth: '170px' }),
			cred.authType === 'ccache' ? credField(210, 'PATH', pathIn) : null,
			testBtn, pill);
	}

	const cInput = h('input', { placeholder: 'host / ip',
		onkeydown: e => { if (e.key === 'Enter') connectClicked(); } });
	const connectForm = h('div', { style: { display: 'flex', gap: '4px', padding: '6px' } },
		h('div.field', { style: { flex: 1 } }, cInput),
		btn('Connect', 'primary', () => connectClicked()));

	main.append(
		h('div.page-head', h('span.title', 'SMB Browser'), crumb, h('span.grow'),
			h('div.toolbar', btn('⚡ Spider secrets', 'primary',
				() => curHost ? runCmd('Find-InterestingFile -Computer ' + curHost) : toast('info', 'connect to a host first')))),
		credBar,
		h('div.split',
			h('div.pane.left', { style: { width: '300px' } },
				h('div.pane-head', h('span', 'Hosts & Shares')), connectForm, hostsEl),
			h('div.pane.fill', filesHead, filesHost)));
	renderCredBar();

	function hostState(hn) {
		return hostShares[hn] || (hostShares[hn] = { expanded: false, shares: null, loading: false });
	}
	/* hosts tree — each host expands into a dropdown of its shares */
	function renderHosts() {
		clear(hostsEl);
		if (!hosts.length) { hostsEl.appendChild(h('div.empty', 'no SMB sessions — connect above')); return; }
		hosts.forEach(hn => {
			const st = hostState(hn);
			const hostNode = h('div.tree-node',
				h('span.twist', st.expanded ? '▾' : '▸'),
				h('span', { class: 'ic t-host', html: objIcon('host') }),
				h('span.lbl', hn));
			hostNode.onclick = () => toggleHost(hn);
			hostsEl.appendChild(hostNode);
			if (!st.expanded) return;
			if (st.loading || st.shares == null) {
				hostsEl.appendChild(h('div.tree-node', { style: { paddingLeft: '32px' } },
					h('span.twist'), h('span.muted.xs', 'loading shares…')));
				return;
			}
			if (st.shares.error) {
				hostsEl.appendChild(h('div.tree-node', { style: { paddingLeft: '32px' } },
					h('span.twist'), h('span.xs', { style: { color: 'var(--red)' } }, st.shares.error)));
				return;
			}
			if (!st.shares.length) {
				hostsEl.appendChild(h('div.tree-node', { style: { paddingLeft: '32px' } },
					h('span.twist'), h('span.muted.xs', '(no shares)')));
				return;
			}
			st.shares.forEach(sh => {
				const sel = hn === curHost && sh.name === curShare;
				let badge = null;
				if (sh.readable || sh.writable) {
					badge = h('span.tag', { style: { marginLeft: '6px' } });
					if (sh.readable) badge.appendChild(h('span', { style: { color: 'var(--accent)' } }, 'R'));
					if (sh.writable) badge.appendChild(h('span', { style: { color: 'var(--red)' } }, 'W'));
				}
				const node = h('div.tree-node', { class: sel ? 'selected' : '',
					style: { paddingLeft: '24px' }, title: sh.access || sh.name },
					h('span.twist'),
					h('span', { class: 'ic', html: objIcon('container') }),
					h('span.lbl', sh.name), badge);
				node.onclick = () => {
					curHost = hn; curShare = sh.name; curPath = '';
					renderHosts(); loadFiles();
				};
				hostsEl.appendChild(node);
			});
		});
	}
	function toggleHost(hn) {
		const st = hostState(hn);
		st.expanded = !st.expanded;
		curHost = hn;
		renderHosts();
		if (st.expanded && !st.loading && (!st.shares || st.shares.error)) loadShares(hn);
	}
	/* connect using whatever the credential bar currently holds */
	async function doConnect(host) {
		const body = Object.assign({ computer: host }, getCreds());
		await api.post('/api/smb/connect', body);
		if (hosts.indexOf(host) < 0) hosts.push(host);
		curHost = host;
		const st = hostState(host);
		st.expanded = true; st.shares = null;
		renderHosts();
		loadShares(host);
	}
	async function connectClicked() {
		const host = cInput.value.trim();
		if (!host) { toast('error', 'enter a host / ip'); return; }
		toast('info', 'connecting to ' + host + '…');
		try { await doConnect(host); cInput.value = ''; toast('success', 'connected to ' + host); }
		catch (e) { toast('error', e.message); }
	}
	/* Test = validate alt creds then bind to the host with them, reporting in the pill */
	async function runTest() {
		if (credMode === 'session') {
			authStatus = { kind: 'session', msg: 'bound session credentials' }; renderCredBar(); return;
		}
		const verr = validateCreds();
		if (verr) { authStatus = { kind: verr.warn ? 'warn' : 'err', msg: verr.msg }; renderCredBar(); return; }
		const host = cInput.value.trim() || curHost;
		if (!host) { authStatus = { kind: 'warn', msg: 'enter a host to test against' }; renderCredBar(); return; }
		authStatus = { kind: 'testing', msg: 'binding to ' + host + ' …' }; renderCredBar();
		try {
			await doConnect(host);
			const who = (cred.domain.trim() ? cred.domain.trim() + '\\' : '') + cred.username.trim();
			authStatus = { kind: 'ok', msg: 'auth ok · ' + who + ' via ' + AUTH_LABEL[cred.authType] };
			cInput.value = '';
		} catch (e) { authStatus = { kind: 'err', msg: e.message }; }
		renderCredBar();
	}
	/* fetch a host's shares into hostShares state, then re-render the tree */
	async function loadShares(host) {
		const st = hostState(host);
		st.loading = true; renderHosts();
		try {
			const data = await api.post('/api/smb/shares', { computer: host });
			st.shares = (Array.isArray(data) ? data : (data && data.shares) || []).map(s => {
				const a = (s && s.attributes) || s || {};
				return { name: a.Name || '', desc: a.Remark || '',
					access: a.Access || '', readable: a.Readable, writable: a.Writable };
			});
		} catch (e) {
			st.shares = { error: e.message };
		}
		st.loading = false;
		renderHosts();
	}
	async function loadFiles() {
		clear(filesHost);
		clear(filesHead); filesHead.append(h('span', 'Files'), h('span.grow'),
			h('span.muted.xs.mono', '\\\\' + curHost + '\\' + curShare + '\\' + curPath));
		crumb.textContent = '/ \\\\' + curHost + '\\' + curShare + (curPath ? '\\' + curPath : '');
		const done = withSpinner(filesHost);
		try {
			const data = await api.post('/api/smb/ls', { computer: curHost, share: curShare, path: curPath });
			done();
			let list = Array.isArray(data) ? data : (data && (data.files || data.entries)) || [];
			/* server returns `modified` as a raw Windows FILETIME (100ns ticks
			   since 1601) string — convert to a readable date for display. */
			const fmtTime = v => {
				const ft = Number(v);
				if (!ft || !isFinite(ft)) return '';
				const d = new Date(ft / 1e4 - 11644473600000);
				return isNaN(d) ? '' : d.toISOString().slice(0, 19).replace('T', ' ');
			};
			const rows = list.map(f => {
				const isDir = !!f.is_directory;
				return { name: f.name || '',
					type: isDir ? 'dir' : 'file', isDir: isDir,
					size: isDir ? '' : (f.size != null ? f.size : ''),
					mtime: fmtTime(f.modified) };
			});
			if (curPath) rows.unshift({ name: '..', type: 'dir', isDir: true, size: '', mtime: '' });
			const g = grid([
				{ key: 'name', label: 'Name', w: 320, render: (v, r) =>
					(r.isDir ? '▸ ' : '  ') + v, color: (v, r) => r.isDir ? 'var(--accent)' : 'var(--text)' },
				{ key: 'type', label: 'Type', w: 70, color: () => 'var(--text-2)' },
				{ key: 'size', label: 'Size', w: 100, color: () => 'var(--text-2)' },
				{ key: 'mtime', label: 'Modified', w: 170, color: () => 'var(--muted)' }
			], { empty: 'empty', onRow: r => {
				if (!r.isDir) return;
				if (r.name === '..') curPath = curPath.split('\\').slice(0, -1).join('\\');
				else curPath = (curPath ? curPath + '\\' : '') + r.name;
				loadFiles();
			}});
			clear(filesHost); filesHost.appendChild(g.el); g.setData(rows);
		} catch (e) { done(); clear(filesHost); filesHost.appendChild(h('div.empty', e.message)); }
	}
	/* seed from existing sessions */
	api.get('/api/smb/sessions').then(d => {
		const sess = (d && d.sessions) || {};
		const list = Array.isArray(sess) ? sess : Object.values(sess);
		list.forEach(s => { const hn = (s && (s.computer || s.host)) || s;
			if (typeof hn === 'string' && hosts.indexOf(hn) < 0) hosts.push(hn); });
		renderHosts();
	}).catch(() => renderHosts());
};

/* ============================ UTILS ============================ */
const TOOLS = [
	{ id: 'kerberoast', name: 'Kerberoast',      risk: 'high',   desc: 'Request TGS for SPN accounts and extract crackable hashes.', cmd: 'Invoke-Kerberoast' },
	{ id: 'asrep',      name: 'AS-REP Roast',    risk: 'high',   desc: 'Pull AS-REP hashes for accounts without Kerberos pre-auth.',  cmd: 'Get-DomainUser -PreauthNotRequired' },
	{ id: 'spnscan',    name: 'SPN Scan',        risk: 'low',    desc: 'Enumerate service principal names across the domain.',        cmd: 'Get-DomainUser -SPN' },
	{ id: 'laps',       name: 'LAPS Reader',     risk: 'medium', desc: 'Read ms-Mcs-AdmPwd where the bound account has access.',      cmd: 'Get-DomainComputer -LAPS' },
	{ id: 'gmsa',       name: 'gMSA Password',   risk: 'medium', desc: 'Read managed service account password blobs.',                cmd: 'Get-DomainGMSA' },
	{ id: 'trusts',     name: 'Trust Mapping',   risk: 'low',    desc: 'Recursively enumerate domain and forest trusts.',             cmd: 'Get-DomainTrustMapping' },
	{ id: 'acl',        name: 'Interesting ACLs',risk: 'medium', desc: 'Find dangerous ACL edges on privileged objects.',             cmd: 'Find-InterestingDomainAcl' },
	{ id: 'unconst',    name: 'Unconstrained',   risk: 'high',   desc: 'List hosts trusted for unconstrained delegation.',            cmd: 'Get-DomainComputer -Unconstrained' },
	{ id: 'rbcd',       name: 'RBCD',            risk: 'high',   desc: 'Resource-based constrained delegation abuse.',                cmd: 'Get-DomainRBCD' },
	{ id: 'gpolocal',   name: 'GPO Local Group', risk: 'medium', desc: 'Map GPO-assigned local group membership.',                   cmd: 'Get-DomainGPOLocalGroup' },
	{ id: 'dcsync',     name: 'DCSync Rights',   risk: 'high',   desc: 'Identify principals with replication (DCSync) rights.',       cmd: 'Get-DomainObjectAcl -Identity "DC=" -ResolveGUIDs' },
	{ id: 'localadmin', name: 'Local Admin',     risk: 'medium', desc: 'Find machines where the current user has local admin.',       cmd: 'Find-LocalAdminAccess' }
];
window.PV.pages.utils = function () {
	const main = $('#main');
	const gridEl = h('div.tools-grid');
	const formHost = h('div.props');
	let sel = TOOLS[0];

	main.append(
		h('div.page-head', h('span.title', 'Utils'), h('span.crumbs', '/ enumeration & abuse tools'), h('span.grow')),
		h('div.split',
			h('div.pane.fill', gridEl),
			h('div.pane.right', { style: { width: '380px' } },
				h('div.pane-head', h('span', 'Run'), h('span.grow')),
				formHost)));

	function riskColor(r) { return r === 'high' ? 'red' : r === 'medium' ? 'yellow' : 'green'; }
	function renderGrid() {
		clear(gridEl);
		TOOLS.forEach(t => gridEl.appendChild(h('div', {
			class: 'tool' + (t === sel ? ' selected' : ''), onclick: () => { sel = t; renderGrid(); renderForm(); }
		},
			h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
				h('span.mono', { style: { width: '24px', height: '24px', display: 'inline-flex',
					alignItems: 'center', justifyContent: 'center', background: 'var(--panel-2)',
					border: '1px solid var(--border-2)', color: 'var(--accent)' } }, '✦'),
				h('span.name', t.name), h('span.grow'),
				tag(t.risk, riskColor(t.risk))),
			h('div.desc', t.desc))));
	}
	function renderForm() {
		clear(formHost);
		const cmdInput = h('input', { type: 'text', value: sel.cmd });
		formHost.appendChild(h('div.form-grid',
			h('div.section-divider', 'COMMAND'),
			h('span.label', 'PowerView command'),
			cmdInput,
			h('div.help', 'edit freely — runs through /api/execute'),
			h('div.section-divider', 'EXECUTION'),
			h('span.label', 'Risk'),
			h('div', tag(sel.risk, riskColor(sel.risk))),
			h('span.label', 'Runs as'),
			h('div.mono.xs.muted', 'current bound session'),
			h('div.section-divider', 'PREVIEW'),
			h('div', { style: { gridColumn: '1 / -1', padding: '6px 8px', background: '#08090b',
				border: '1px solid var(--border)', fontFamily: 'var(--font-mono)',
				fontSize: 'var(--fs-xs)', color: 'var(--text-2)', lineHeight: 1.6 } },
				h('div', h('span', { style: { color: 'var(--accent)' } }, '$ '),
					h('span', { id: 'util-prev' }, sel.cmd))),
			h('div', { style: { gridColumn: '1 / -1', display: 'flex', gap: '6px',
				justifyContent: 'flex-end', paddingTop: '8px' } },
				btn('▷ Run', 'primary', () => runCmd(cmdInput.value)))));
		cmdInput.addEventListener('input', () => { const p = $('#util-prev'); if (p) p.textContent = cmdInput.value; });
	}
	renderGrid(); renderForm();
};

/* ============================ SETTINGS ============================ */
window.PV.pages.settings = function () {
	const main = $('#main');
	const formHost = h('div.pane.fill', { style: { overflow: 'auto' } });
	const cats = ['Connection', 'Query Options', 'Appearance', 'Raw Config'];
	const catEl = h('div.tree');

	main.append(
		h('div.page-head', h('span.title', 'Settings'), h('span.crumbs', '/ session & app preferences'),
			h('span.grow')),
		h('div.split',
			h('div.pane.left', { style: { width: '200px' } },
				h('div.pane-head', h('span', 'Categories')), catEl),
			formHost));

	cats.forEach((c, i) => catEl.appendChild(h('div.tree-node' + (i === 0 ? '.selected' : ''),
		{ onclick: () => { $$('.tree-node', catEl).forEach(n => n.classList.remove('selected'));
			catEl.children[i].classList.add('selected');
			const sec = $('#sec-' + i); if (sec) sec.scrollIntoView({ block: 'start' }); } },
		h('span.twist'), h('span.ic', '▸'), h('span.lbl', c))));

	function ro(v) { return h('input', { type: 'text', value: v == null ? '' : String(v), readonly: 'readonly' }); }
	function toggle(checked, onChange) {
		const sel = h('select', h('option', { value: 'on' }, 'enabled'), h('option', { value: 'off' }, 'disabled'));
		sel.value = checked ? 'on' : 'off';
		sel.onchange = () => onChange(sel.value === 'on');
		return sel;
	}

	(async () => {
		let cinfo = {}, settings = {};
		try { cinfo = await api.get('/api/connectioninfo'); } catch (e) {}
		try { settings = await api.get('/api/settings'); } catch (e) {}

		const fg = h('div.form-grid');
		const state = { obfuscate: !!settings.obfuscate, no_cache: !!settings.no_cache, no_vuln_check: !!settings.no_vuln_check };
		async function save() {
			try { await api.post('/api/set/settings', state); toast('success', 'settings updated'); }
			catch (e) { toast('error', e.message); }
		}

		fg.append(
			h('div.section-divider', { id: 'sec-0' }, 'CONNECTION'),
			h('span.label', 'Domain'), ro(cinfo.domain),
			h('span.label', 'Domain controller'), ro(cinfo.ldap_address),
			h('span.label', 'Protocol'), ro((cinfo.protocol || '').toUpperCase()),
			h('span.label', 'Username'), ro(cinfo.username),
			h('span.label', 'Nameserver'), ro(cinfo.nameserver),
			h('span.label', 'Status'), ro(cinfo.status),

			h('div.section-divider', { id: 'sec-1' }, 'QUERY OPTIONS'),
			h('span.label', 'Obfuscate queries'),
			toggle(state.obfuscate, v => { state.obfuscate = v; save(); }),
			h('span.label', 'Query cache'),
			toggle(!state.no_cache, v => { state.no_cache = !v; save(); }),
			h('span.label', 'Vulnerability checks'),
			toggle(!state.no_vuln_check, v => { state.no_vuln_check = !v; save(); }),
			h('span.label', ''), h('div', btn('Clear cache', null,
				() => api.get('/api/clear-cache').then(() => toast('success', 'cache cleared')).catch(e => toast('error', e.message)))));

		/* appearance */
		fg.append(h('div.section-divider', { id: 'sec-2' }, 'APPEARANCE'));
		const tw = (function () { try { return JSON.parse(localStorage.getItem('pv-tweaks') || '{}'); } catch (e) { return {}; } })();
		fg.append(
			h('span.label', 'Theme controls'),
			h('div.mono.xs.muted', 'use the View ▸ menu in the top bar for accent, density, font scale & background tone'));

		/* raw config */
		fg.append(h('div.section-divider', { id: 'sec-3' }, 'RAW CONFIG (read-only)'));
		fg.append(h('span.label', 'powerview args'),
			h('textarea', { rows: 10, readonly: 'readonly' }, JSON.stringify(settings, null, 2)));

		formHost.appendChild(fg);
	})();
};
})();
