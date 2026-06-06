/* powerview.py web ui — object pages: DNS, CA, OUs, GPOs */
(function () {
"use strict";
const { h, $, clear, api, attr, objIcon, grid, tag, btn, propsView, toast, withSpinner, runCmd, inspectorPane, modal } = window.PV;


/* ---- DNS record helpers ---- */
function dnsTypeColor(t) {
	t = String(t || '').toUpperCase();
	if (t === 'SOA' || t === 'NS') return 'blue';
	if (t === 'A' || t === 'AAAA') return 'green';
	if (t === 'CNAME') return 'magenta';
	if (t === 'SRV') return 'yellow';
	return 'gray';
}
/* the value field varies by record type: A/AAAA/NS -> Address, SRV -> Name:Port,
   CNAME/PTR/SOA -> Name / Primary Server; a ZERO (tombstoned node) has none. */
function dnsValue(a, t) {
	if (String(t).toUpperCase() === 'SRV') {
		const tgt = attr(a, 'Name') || '';
		const port = attr(a, 'Port');
		return (tgt && port != null) ? tgt + ':' + port : tgt;
	}
	return attr(a, 'Address') || attr(a, 'Name') || attr(a, 'Primary Server') || attr(a, 'Data') || '';
}
/* wpad / isatap records are classic DNS-spoofing (MITM) vectors */
function dnsSuspicious(name) {
	const first = String(name || '').toLowerCase().split('.')[0];
	return first === 'wpad' || first === 'isatap';
}

/* + Record dialog — Add-DomainDNSRecord creates an A record (recordname +
   IPv4) in the given zone; the backend only supports the A record type. */
function addDnsRecordModal(zone, onDone) {
	const zoneIn = h('input', { value: zone || '', readonly: 'readonly', style: { color: 'var(--muted)' } });
	const nameIn = h('input', { placeholder: 'record name, e.g. wpad', spellcheck: 'false', autocomplete: 'off' });
	const addrIn = h('input', { placeholder: 'IPv4 address, e.g. 10.0.0.50', spellcheck: 'false', autocomplete: 'off' });
	const result = h('div.form-result'); result.hidden = true;
	const fld = (label, ctl) => h('div', h('div.lbl', label), ctl);
	const body = h('div.form-stack',
		fld('Zone', zoneIn),
		fld('Record name', nameIn),
		fld('IPv4 address', addrIn),
		h('div.form-help', { html: 'Creates an <span class="em">A record</span> '
			+ '(a <span class="em">dnsNode</span> object) in the zone. Add-DomainDNSRecord only adds A records.' }),
		result);
	const m = modal({ cmd: 'Add-DomainDNSRecord', subject: zone || 'new record', width: 460, body: body });
	const submit = btn('Add record', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		const zn = zoneIn.value.trim(), nm = nameIn.value.trim(), ip = addrIn.value.trim();
		if (!zn) { toast('error', 'no zone selected'); return; }
		if (!nm) { toast('error', 'enter a record name'); return; }
		if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || ip.split('.').some(o => +o > 255)) {
			toast('error', 'enter a valid IPv4 address'); return;
		}
		/* the backend strips a trailing '.<zone>' suffix from the record name
		   — mirror it (same '.'-separator guard) so the result echoes the
		   name actually stored. */
		let stored = nm;
		if (stored.toLowerCase().endsWith('.' + zn.toLowerCase()))
			stored = stored.slice(0, -(zn.length + 1));
		submit.disabled = true; submit.textContent = 'Adding…';
		try {
			const r = await api.op('add', 'domaindnsrecord', { recordname: nm, recordaddress: ip, zonename: zn });
			if (r === false || r == null) throw new Error("add failed for '" + nm + "' in " + zn + ' (zone not found or access denied)');
			nameIn.disabled = addrIn.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] A record '" + stored + "' → " + ip + ' added to ' + zn;
			toast('success', "DNS A record '" + stored + "' added");
			if (onDone) onDone();
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Add record';
		}
	}
}

/* ============================ DNS ============================ */
window.PV.pages.dns = function () {
	const main = $('#main');
	const zoneTree = h('div.tree');
	const crumb = h('span.crumbs');
	const recHost = h('div.table-wrap');
	let currentZone = null;
	main.append(
		h('div.page-head', h('span.title', 'DNS'), crumb, h('span.grow'),
			h('div.toolbar',
				btn('⟲ Refresh', null, () => loadZones()),
				btn('+ Record', null, () => {
					if (!currentZone) { toast('error', 'select a zone first'); return; }
					addDnsRecordModal(currentZone, () => loadRecords(currentZone));
				}))),
		h('div.split',
			h('div.pane.left', { style: { width: '230px' } },
				h('div.pane-head', h('span', 'Zones')), zoneTree),
			h('div.pane.fill', recHost)));

	async function loadRecords(zone) {
		currentZone = zone;
		clear(recHost);
		const done = withSpinner(recHost);
		try {
			const data = await api.op('get', 'domaindnsrecord', { zonename: zone });
			done();
			/* explicit Name/Type/TTL/Value columns — the API returns a binary
			   dnsRecord blob + metadata that must NOT be shown raw, and the
			   value lives in a different field per record type. */
			const rows = (Array.isArray(data) ? data : []).map(e => {
				const a = e.attributes || {};
				const name = attr(a, 'name') || '';
				const type = attr(a, 'RecordType') || '?';
				return { name: name, type: type, ttl: attr(a, 'TTL'),
					value: dnsValue(a, type), suspicious: dnsSuspicious(name) };
			});
			const g = grid([
				{ key: 'name', label: 'Name', w: 280, color: () => 'var(--accent)' },
				{ key: 'type', label: 'Type', w: 90, render: v => tag(v, dnsTypeColor(v)) },
				{ key: 'ttl', label: 'TTL', w: 80, color: () => 'var(--text-2)',
					render: v => (v == null || v === '') ? h('span.muted', '—') : String(v) },
				{ key: 'value', label: 'Value', render: (v, r) => {
					if (!v) return h('span.muted', '—');
					if (!r.suspicious) return h('span', v);
					return h('span', { style: { color: 'var(--red)' } }, v,
						h('span.mono.xs', { style: { color: 'var(--red)', marginLeft: '8px' } },
							'← suspicious / unverified'));
				} }
			], { empty: 'no records in this zone', sort: 'name' });
			clear(recHost); recHost.appendChild(g.el); g.setData(rows);
			crumb.textContent = '/ ' + zone + ' · ' + rows.length + ' records';
		} catch (e) { done(); clear(recHost); recHost.appendChild(h('div.empty', e.message)); }
	}
	async function loadZones() {
		clear(zoneTree);
		const done = withSpinner(zoneTree);
		try {
			const data = await api.get('/api/get/domaindnszone');
			done(); clear(zoneTree);
			const zones = (data || []).map(e => {
				const a = e.attributes || {};
				return attr(a, 'name') || attr(a, 'zoneName') || attr(a, 'dc') || e;
			}).filter(Boolean);
			if (!zones.length) { zoneTree.appendChild(h('div.empty', 'no zones')); return; }
			zones.forEach((z, i) => {
				const node = h('div.tree-node', h('span.twist'),
					h('span', { class: 'ic t-zone', html: objIcon('zone') }), h('span.lbl', z));
				node.onclick = () => {
					$('.tree-node.selected', zoneTree) && $('.tree-node.selected', zoneTree).classList.remove('selected');
					node.classList.add('selected');
					loadRecords(z);
				};
				zoneTree.appendChild(node);
				if (i === 0) node.click();
			});
		} catch (e) { done(); clear(zoneTree); zoneTree.appendChild(h('div.empty', e.message)); }
	}
	loadZones();
};

/* ---- CA / ADCS helpers ---- */
function caAsList(v) { return Array.isArray(v) ? v : (v == null || v === '' ? [] : [v]); }
/* the Vulnerable attribute is a list of "ESCn - <principals>" strings */
function caEscList(vuln) {
	const out = [];
	caAsList(vuln).forEach(v => {
		const m = String(v).match(/^ESC\d+/i);
		if (m && out.indexOf(m[0].toUpperCase()) < 0) out.push(m[0].toUpperCase());
	});
	return out;
}
function caKvRow(k, v, color) {
	return h('div.row', { style: { gridTemplateColumns: '170px 1fr' } },
		h('span.k.mono', k),
		h('span.v', { style: color ? { color: color } : null },
			(v == null || v === '') ? '—' : String(v)));
}
function caTemplateRow(e) {
	const a = e.attributes || {};
	const vuln = caAsList(a.Vulnerable), esc = caEscList(vuln), enroll = caAsList(a['Enrollment Rights']);
	const eku = caAsList(a.pKIExtendedKeyUsage);
	return {
		name: attr(a, 'displayName') || attr(a, 'cn') || attr(a, 'name') || '',
		vulnerable: vuln.length > 0, esc: esc, escStr: esc.join(' '),
		enabled: a.Enabled === true || String(a.Enabled).toLowerCase() === 'true',
		owner: attr(a, 'Owner') || '', enroll: enroll.join(', '),
		eku: eku.length ? eku.join(', ')
			: (a['Any Purpose'] === true ? 'Any Purpose'
			 : a['Enrollment Agent'] === true ? 'Certificate Request Agent' : ''),
		vulnList: vuln, enrollList: enroll, attrs: a,
		dn: e.dn || attr(a, 'distinguishedName') || ''
	};
}
function caRow(e) {
	const a = e.attributes || {};
	return {
		name: attr(a, 'displayName') || attr(a, 'cn') || attr(a, 'name') || '',
		dns: attr(a, 'dNSHostName') || '',
		templates: caAsList(a.certificateTemplates).length,
		dn: e.dn || attr(a, 'distinguishedName') || '', attrs: a
	};
}
function caTemplateDetail(r, host) {
	clear(host);
	const a = r.attrs;
	host.appendChild(h('div', { style: { padding: '10px 12px', borderBottom: '1px solid var(--border)' } },
		h('div.mono', { style: { fontSize: '13px', color: 'var(--text)', fontWeight: '600' } }, r.name),
		h('div', { style: { display: 'flex', gap: '4px', marginTop: '6px', flexWrap: 'wrap' } },
			r.esc.map(c => tag(c, 'red')).concat([r.enabled ? tag('enabled', 'green') : tag('disabled', 'gray')]))));
	const ess = (Number(a['msPKI-Certificate-Name-Flag']) & 1) === 1;
	const flags = h('div', { style: { padding: '4px 0' } },
		caKvRow('enabled', r.enabled ? 'true' : 'false', r.enabled ? null : 'var(--muted)'),
		caKvRow('owner', r.owner),
		caKvRow('certificate authority', caAsList(a['Certificate Authorities']).join(', ')),
		caKvRow('eku', r.eku),
		caKvRow('manager approval', a.ManagerApproval === true ? 'required' : 'not required'),
		caKvRow('enrollee supplies subject', ess ? 'TRUE' : 'false', ess ? 'var(--red)' : null),
		caKvRow('schema version', a['msPKI-Template-Schema-Version']));
	const enroll = h('div', { style: { padding: '4px 12px' } }, r.enrollList.length
		? r.enrollList.map(p => h('div.mono.sm', { style: { padding: '2px 0', color: 'var(--text-2)' } }, '↳ ' + p))
		: [h('span.muted', '—')]);
	const groups = [{ title: 'Flags', body: flags },
		{ title: 'Enrollment Rights (' + r.enrollList.length + ')', body: enroll }];
	if (r.vulnList.length) groups.push({ title: 'Findings (' + r.vulnList.length + ')',
		body: h('div', { style: { padding: '6px 12px' } }, r.vulnList.map(v =>
			h('div.mono.sm', { style: { padding: '3px 0', color: 'var(--red)', lineHeight: 1.5 } }, '⚠  ' + v))) });
	host.appendChild(propsView(groups));
}
function caDetail(r, host) {
	clear(host);
	host.appendChild(h('div', { style: { padding: '10px 12px', borderBottom: '1px solid var(--border)' } },
		h('div.mono', { style: { fontSize: '13px', color: 'var(--text)', fontWeight: '600' } }, r.name)));
	host.appendChild(propsView([{ title: 'Certificate Authority', body: h('div', { style: { padding: '4px 0' } },
		caKvRow('dns host', r.dns),
		caKvRow('templates published', String(r.templates)),
		caKvRow('ca certificate dn', attr(r.attrs, 'cACertificateDN')),
		caKvRow('distinguished name', r.dn)) }]));
}

/* ============================ CA ============================ */
window.PV.pages.ca = function () {
	const main = $('#main');
	const crumb = h('span.crumbs');
	const tabsEl = h('div.tabs');
	const tableHost = h('div.table-wrap');
	const detailHost = h('div.props', h('div.empty', 'select a row'));
	const detailSub = h('span.muted.xs.mono');
	let curGrid = null;
	const insp = inspectorPane('Detail', detailSub, detailHost, () => curGrid);
	main.append(
		h('div.page-head', h('span.title', 'CA / ADCS'), crumb, h('span.grow'),
			h('div.toolbar', btn('⟲ Refresh', null, () => loadTab()),
				btn('⚡ Auto-find ESC', 'primary', () => runCmd('Get-DomainCATemplate -Vulnerable')))),
		tabsEl,
		h('div.split', h('div.pane.fill', tableHost), insp.el));

	let tab = 'templates';
	const TABS = [{ k: 'templates', l: 'Templates' }, { k: 'cas', l: 'Certificate Authorities' }];
	function buildTabs() {
		clear(tabsEl);
		TABS.forEach(t => tabsEl.appendChild(h('div',
			{ class: 'tab' + (t.k === tab ? ' active' : ''), onclick: () => { tab = t.k; buildTabs(); loadTab(); } }, t.l)));
	}
	async function loadTab() {
		insp.hide();
		clear(tableHost);
		const done = withSpinner(tableHost);
		try {
			let cols, rows, onRow;
			if (tab === 'templates') {
				const data = await api.op('get', 'domaincatemplate', { resolve_sids: true });
				done();
				rows = (Array.isArray(data) ? data : []).map(caTemplateRow);
				cols = [
					{ key: 'name', label: 'Template', w: 200,
						color: (v, r) => r.vulnerable ? 'var(--red)' : 'var(--accent)' },
					{ key: 'vulnerable', label: 'Vulnerable', w: 95,
						render: v => v ? tag('YES', 'red') : h('span.muted', '—') },
					{ key: 'escStr', label: 'ESC', w: 130, render: (v, r) => r.esc.length
						? h('span', r.esc.map(c => h('span', { style: { marginRight: '4px' } }, tag(c, 'red'))))
						: h('span.muted', '—') },
					{ key: 'enabled', label: 'Enabled', w: 80,
						render: v => v ? tag('on', 'green') : tag('off', 'gray') },
					{ key: 'owner', label: 'Owner', w: 190, color: () => 'var(--text-2)' },
					{ key: 'enroll', label: 'Enrollment Rights', w: 250, color: () => 'var(--text-2)' },
					{ key: 'eku', label: 'EKU', color: () => 'var(--muted)' }
				];
				onRow = r => { detailSub.textContent = r.name; caTemplateDetail(r, detailHost); insp.show(); };
			} else {
				const data = await api.get('/api/get/domainca');
				done();
				rows = (Array.isArray(data) ? data : []).map(caRow);
				cols = [
					{ key: 'name', label: 'CA Name', w: 240, color: () => 'var(--accent)' },
					{ key: 'dns', label: 'Host', w: 250, color: () => 'var(--text-2)' },
					{ key: 'templates', label: 'Templates', w: 110, color: () => 'var(--text-2)' },
					{ key: 'dn', label: 'Distinguished Name', color: () => 'var(--muted)' }
				];
				onRow = r => { detailSub.textContent = r.name; caDetail(r, detailHost); insp.show(); };
			}
			const g = grid(cols, { empty: 'none found', sort: 'name',
				rowKey: r => r.dn || r.name, onRow: onRow });
			clear(tableHost); tableHost.appendChild(g.el); g.setData(rows);
			curGrid = g;
			const vuln = tab === 'templates' ? rows.filter(r => r.vulnerable).length : 0;
			crumb.textContent = '/ ' + rows.length + ' ' + tab
				+ (tab === 'templates' ? ' · ' + vuln + ' vulnerable' : '');
		} catch (e) { done(); clear(tableHost); tableHost.appendChild(h('div.empty', e.message)); }
	}
	buildTabs(); loadTab();
};

/* ============================ OUs ============================ */
window.PV.pages.ous = function () {
	const main = $('#main');
	const crumb = h('span.crumbs');
	const treeEl = h('div.tree');
	const tableHost = h('div.table-wrap');
	main.append(
		h('div.page-head', h('span.title', 'Organizational Units'), crumb, h('span.grow'),
			h('div.toolbar', btn('⟲ Refresh', null, () => load()))),
		h('div.split',
			h('div.pane.left', { style: { width: '340px' } },
				h('div.pane-head', h('span', 'Tree')), treeEl),
			h('div.pane.fill',
				h('div.pane-head', h('span', 'OUs'), h('span.grow'), h('span.muted.xs.mono', 'flat list')),
				tableHost)));

	function buildTree(rows) {
		clear(treeEl);
		const root = { kids: {} };
		rows.forEach(r => {
			const parts = (r.dn || '').split(',').reverse()
				.filter(p => /^OU=/i.test(p)).map(p => p.slice(3));
			let cur = root;
			parts.forEach(p => { cur.kids[p] = cur.kids[p] || { kids: {} }; cur = cur.kids[p]; });
		});
		function render(node, depth) {
			Object.keys(node.kids).sort().forEach(k => {
				treeEl.appendChild(h('div.tree-node', { style: { paddingLeft: (4 + depth * 14) + 'px' } },
					h('span.twist', '▾'), h('span', { class: 'ic t-ou', html: objIcon('ou') }),
					h('span.lbl', k)));
				render(node.kids[k], depth + 1);
			});
		}
		treeEl.appendChild(h('div.tree-node.selected',
			h('span.twist', '▾'), h('span', { class: 'ic t-domain', html: objIcon('domain') }),
			h('span.lbl', 'domain root')));
		render(root, 1);
	}
	async function load() {
		clear(tableHost);
		const done = withSpinner(tableHost);
		try {
			const data = await api.op('get', 'domainou', { properties: ['name', 'distinguishedName', 'gPLink', 'description'] });
			done();
			const rows = (data || []).map(e => {
				const a = e.attributes || {};
				const dn = e.dn || attr(a, 'distinguishedName') || '';
				const links = (String(attr(a, 'gPLink') || '').match(/LDAP:\/\//g) || []).length;
				return { name: attr(a, 'name') || '', dn: dn, gpos: links,
					desc: attr(a, 'description') || '' };
			});
			buildTree(rows);
			const g = grid([
				{ key: 'name', label: 'Name', w: 180, color: () => 'var(--accent)' },
				{ key: 'dn', label: 'Distinguished Name', color: () => 'var(--accent)' },
				{ key: 'gpos', label: 'GPOs Linked', w: 110, color: v => v ? 'var(--text)' : 'var(--muted)' },
				{ key: 'desc', label: 'Description', w: 200, color: () => 'var(--text-2)' }
			], { empty: 'no OUs', sort: 'dn' });
			clear(tableHost); tableHost.appendChild(g.el); g.setData(rows);
			crumb.textContent = '/ ' + rows.length + ' OUs';
		} catch (e) { done(); clear(tableHost); tableHost.appendChild(h('div.empty', e.message)); }
	}
	load();
};

/* ---- GPO helpers ---- */
/* GPO flags: 0 = enabled, 1 = user cfg disabled, 2 = computer cfg disabled, 3 = all off */
function gpoState(flags) {
	flags = Number(flags) || 0;
	if (flags === 3) return ['off', 'gray'];
	if (flags & 1 || flags & 2) return ['partial', 'yellow'];
	return ['on', 'green'];
}
const GPO_SEV_RANK = { high: 3, medium: 2, low: 1 };
function gpoFindingTagColor(sev) {
	return sev === 'high' ? 'red' : sev === 'medium' ? 'yellow' : 'gray';
}
function gpoRow(e) {
	const a = e.attributes || {};
	const links = Array.isArray(a.links) ? a.links : [];
	const findings = Array.isArray(a.findings) ? a.findings : [];
	let worst = '';
	findings.forEach(f => { if ((GPO_SEV_RANK[f.severity] || 0) > (GPO_SEV_RANK[worst] || 0)) worst = f.severity; });
	return {
		name: attr(a, 'displayName') || attr(a, 'name') || '',
		guid: attr(a, 'cn') || attr(a, 'name') || '',
		flags: Number(attr(a, 'flags')) || 0,
		version: attr(a, 'versionNumber'),
		created: attr(a, 'whenCreated') || '',
		modified: attr(a, 'whenChanged') || '',
		path: attr(a, 'gPCFileSysPath') || '',
		links: links, linkCount: links.length,
		findings: findings, worst: worst,
		dn: e.dn || attr(a, 'distinguishedName') || '', attrs: a
	};
}
/* short label for a SOM dn — the first RDN value (e.g. "Domain Controllers") */
function somLabel(dn) {
	const m = String(dn || '').match(/^[A-Za-z]+=([^,]+)/);
	return m ? m[1] : (dn || '?');
}
/* ---- GPO settings tree (parsed from SYSVOL via Get-DomainGPOSettings) ----
   Risky-setting classification is authoritative on the server side
   (Get-DomainGPOSettings attaches a `findings` list); the tree builder
   below mirrors that classifier's traversal so each finding's (path, name)
   pair lines up with the matching tree leaf. */
function gpoFlattenObj(obj, prefix, out) {
	for (const k in (obj || {})) {
		const key = prefix ? prefix + ' / ' + k : k;
		const v = obj[k];
		if (v && typeof v === 'object' && !Array.isArray(v)) gpoFlattenObj(v, key, out);
		else out[key] = Array.isArray(v) ? v.join(', ') : (v == null ? '' : String(v));
	}
	return out;
}
function gpoLeaf(name, value, props, path) {
	const v = value == null ? '' : (Array.isArray(value) ? value.join(', ') : String(value));
	return { kind: 'leaf', name: String(name), value: v, props: props || null,
		path: path, finding: null };
}
function gpoObjLeaf(obj, i, path) {
	const props = gpoFlattenObj(obj, '', {});
	const name = obj.name || obj.uid || obj.key || obj.subkey || obj.title || ('item ' + (i + 1));
	return gpoLeaf(name, '', props, path);
}
/* recursively turn a parsed config dict into cat / leaf tree nodes —
   keeps raw dict keys (no path rewriting) so leaf (path, name) matches
   the server-side _walk_gpo_settings traversal exactly. */
function gpoBuildNodes(obj, path) {
	const out = [];
	Object.keys(obj || {}).forEach(k => {
		const v = obj[k], childPath = path.concat(k);
		if (Array.isArray(v)) {
			const scalar = v.every(x => x == null || typeof x !== 'object');
			out.push({ kind: 'cat', label: k, path: childPath, children: scalar
				? v.map(s => gpoLeaf(String(s), '', null, childPath))
				: v.map((o, i) => gpoObjLeaf(o, i, childPath)) });
		} else if (v && typeof v === 'object') {
			out.push({ kind: 'cat', label: k, path: childPath,
				children: gpoBuildNodes(v, childPath) });
		} else {
			out.push(gpoLeaf(k, v, null, path));
		}
	});
	return out;
}
/* attach server-side findings to matching tree leaves by (path, name) */
function gpoApplyFindings(tree, serverFindings) {
	const map = {};
	(serverFindings || []).forEach(f => {
		map[(f.path || []).join(' ') + ' ' + f.name] = f;
	});
	gpoWalkLeaves(tree, l => {
		l.finding = map[l.path.join(' ') + ' ' + l.name] || null;
	});
}
/* build the top-level Computer / User Configuration tree from a settings entry */
function gpoSettingsTree(entry) {
	const a = (entry && entry.attributes) || {};
	const tree = [];
	const mc = a.machineConfig, uc = a.userConfig;
	if (mc && Object.keys(mc).length)
		tree.push({ kind: 'cat', root: true, label: 'Computer Configuration',
			path: ['Computer Configuration'], children: gpoBuildNodes(mc, ['Computer Configuration']) });
	if (uc && Object.keys(uc).length)
		tree.push({ kind: 'cat', root: true, label: 'User Configuration',
			path: ['User Configuration'], children: gpoBuildNodes(uc, ['User Configuration']) });
	return tree;
}
function gpoWalkLeaves(nodes, fn) {
	nodes.forEach(n => { if (n.kind === 'leaf') fn(n); else gpoWalkLeaves(n.children || [], fn); });
}

/* ============================ GPOs ============================
   Three-pane drill-down (Group Policy Management Editor style):
   GPO list -> Settings tree -> tabbed detail (Setting / Overview / Links /
   Permissions). The settings tree is parsed lazily from SYSVOL per GPO. */
window.PV.pages.gpos = function () {
	const main = $('#main');
	let gpos = [], selGpo = null, tab = 'settings', selLeaf = null, q = '';
	const settingsCache = {};   /* guid -> {tree,count,findings} | {error} */
	const aclCache = {};        /* dn   -> [ace] | {error} */
	const expanded = {};        /* tree path string -> open? */

	const crumb = h('span.crumbs');
	const search = window.PV.searchField(v => { q = v; renderList(); }, 'name or GUID…');
	const listHost = h('div', { style: { overflow: 'auto', flex: '1', minHeight: '0' } });
	const listCount = h('span.muted.mono.xs');
	const treeHost = h('div.gpo-tree');
	const treeCount = h('span.muted.mono.xs');
	const treeFlag = h('span', { style: { marginLeft: '6px' } });
	const tabsEl = h('div.tabs');
	const detailHost = h('div.gpo-detail');

	main.append(
		h('div.page-head', h('span.title', 'Group Policy Objects'), crumb, h('span.grow'),
			h('div.toolbar', search,
				btn('⟲ Refresh', null, () => load()),
				btn('Get-DomainGPOLocalGroup', null, () => runCmd('Get-DomainGPOLocalGroup')))),
		h('div.split',
			h('div.pane.left', { style: { width: '280px' } },
				h('div.pane-head', h('span', 'GPOs'), h('span.grow'), listCount),
				listHost),
			h('div.pane', { style: { width: '380px', borderRight: '1px solid var(--border)',
				background: 'var(--panel)' } },
				h('div.pane-head', h('span', 'Settings'), h('span.grow'), treeCount, treeFlag),
				treeHost),
			h('div.pane.fill', { style: { background: 'var(--bg)' } }, tabsEl, detailHost)));

	function emptyDetail(icon, title, sub) {
		return h('div.empty-detail', h('div.icon', icon), h('div', title),
			sub ? h('div', { style: { fontSize: '11px' } }, sub) : null);
	}

	/* ── left: GPO list ── */
	function renderList() {
		clear(listHost);
		const view = gpos.filter(g => !q
			|| g.name.toLowerCase().indexOf(q.toLowerCase()) > -1
			|| g.guid.toLowerCase().indexOf(q.toLowerCase()) > -1);
		listCount.textContent = view.length;
		crumb.textContent = '/ ' + gpos.length + ' GPOs · '
			+ gpos.filter(g => g.findings.length).length + ' flagged';
		if (!view.length) { listHost.appendChild(h('div.empty', 'no GPOs')); return; }
		view.forEach(g => {
			const s = gpoState(g.flags);
			const stColor = s[0] === 'off' ? 'var(--muted)'
				: s[1] === 'yellow' ? 'var(--yellow)' : 'var(--accent)';
			const cached = settingsCache[g.guid];
			listHost.appendChild(h('div', { class: 'gpo-list-row'
				+ (selGpo && selGpo.guid === g.guid ? ' selected' : '')
				+ (g.findings.length ? ' flagged' : ''), onclick: () => selectGpo(g) },
				h('div.top', h('span.nm', g.name),
					g.findings.slice(0, 1).map(f => tag(f.label || f.id, gpoFindingTagColor(f.severity)))),
				h('div.meta',
					h('span', { style: { color: stColor } },
						s[0] === 'off' ? '○ off' : '● ' + s[0]),
					g.links.some(l => l.enforced)
						? h('span', { style: { color: 'var(--yellow)' } }, 'enforced') : null,
					h('span', h('span.num', String(g.linkCount)),
						' link' + (g.linkCount === 1 ? '' : 's')),
					cached && !cached.error
						? h('span', h('span.num', String(cached.count)), ' set') : null,
					h('span', { style: { marginLeft: 'auto' } },
						String(g.modified || '').split(' ')[0]))));
		});
	}

	function selectGpo(g) {
		selGpo = g; tab = 'settings'; selLeaf = null;
		renderList(); renderTabs(); renderTree(); renderDetail();
		loadSettings(g);
	}

	/* ── middle: settings tree (lazy SYSVOL scan per GPO) ── */
	async function loadSettings(g) {
		if (settingsCache[g.guid]) {
			applyDefaultLeaf(g); renderTree(); renderDetail(); renderList();
			return;
		}
		renderTree();   /* shows spinner */
		try {
			const data = await api.op('get', 'domaingposettings', { identity: g.guid });
			const entry = Array.isArray(data) ? data[0] : data;
			const tree = entry ? gpoSettingsTree(entry) : [];
			/* findings are classified server-side — attach them to leaves */
			gpoApplyFindings(tree, (entry && entry.attributes && entry.attributes.findings) || []);
			let count = 0; const findings = [];
			gpoWalkLeaves(tree, l => { count++; if (l.finding) findings.push(l); });
			tree.forEach(n => { expanded[n.path.join('/')] = true; });
			settingsCache[g.guid] = { tree: tree, count: count, findings: findings };
		} catch (e) {
			settingsCache[g.guid] = { error: e.message };
		}
		if (selGpo && selGpo.guid === g.guid) {
			applyDefaultLeaf(g); renderTree(); renderDetail(); renderList();
		}
	}
	/* default the Setting tab to the first risky leaf, if any */
	function applyDefaultLeaf(g) {
		const c = settingsCache[g.guid];
		if (selLeaf || !c || c.error) return;
		if (c.findings.length) selLeaf = c.findings[0];
	}

	function renderTree() {
		clear(treeHost); clear(treeFlag); treeCount.textContent = '';
		if (!selGpo) {
			treeHost.appendChild(emptyDetail('▤', 'No GPO selected', 'Pick a GPO from the list.'));
			return;
		}
		const c = settingsCache[selGpo.guid];
		if (!c) { treeHost.appendChild(h('div.empty', h('div.spinner'))); return; }
		if (c.error) {
			treeHost.appendChild(emptyDetail('∅', 'SYSVOL scan failed', c.error));
			return;
		}
		treeCount.textContent = c.count + ' defined';
		if (c.findings.length)
			treeFlag.appendChild(h('span.tag.red', { style: { height: '18px' } }, '⚠ ' + c.findings.length));
		if (!c.tree.length) {
			treeHost.appendChild(emptyDetail('∅', 'No settings defined',
				'This GPO holds no policy or preference values in SYSVOL.'));
			return;
		}
		c.tree.forEach(n => renderNode(n, 0));
	}
	function renderNode(node, depth) {
		const pad = { paddingLeft: (12 + depth * 14) + 'px' };
		if (node.kind === 'leaf') {
			treeHost.appendChild(h('div', { style: pad,
				class: 'gpo-tree-node leaf' + (selLeaf === node ? ' selected' : '')
					+ (node.finding ? ' risky' : ''),
				onclick: () => { selLeaf = node; tab = 'settings';
					renderTabs(); renderTree(); renderDetail(); } },
				h('span.twist', '·'),
				h('span', { class: 'ic', html: objIcon('obj') }),
				h('span.lbl', node.name),
				node.finding ? h('span.state.off', '⚠') : null));
			return;
		}
		const key = node.path.join('/'), open = !!expanded[key];
		treeHost.appendChild(h('div', { style: pad,
			class: 'gpo-tree-node ' + (node.root ? 'root' : 'cat'),
			onclick: () => { expanded[key] = !open; renderTree(); } },
			h('span.twist', open ? '▾' : '▸'),
			h('span', { class: 'ic', html: objIcon(node.root ? 'container' : 'ou') }),
			h('span.lbl', node.label)));
		if (open) (node.children || []).forEach(c => renderNode(c, depth + 1));
	}

	/* ── right: tabbed detail ── */
	function renderTabs() {
		clear(tabsEl);
		if (!selGpo) return;
		[
			{ id: 'settings', l: 'Setting' },
			{ id: 'overview', l: 'Overview' },
			{ id: 'links', l: 'Links (' + selGpo.linkCount + ')' },
			{ id: 'permissions', l: 'Permissions' }
		].forEach(t => tabsEl.appendChild(h('div',
			{ class: 'tab' + (t.id === tab ? ' active' : ''),
			  onclick: () => { tab = t.id;
				if (t.id === 'permissions') loadAcl(selGpo);
				renderTabs(); renderDetail(); } }, t.l)));
	}
	function renderDetail() {
		clear(detailHost);
		if (!selGpo) {
			detailHost.appendChild(emptyDetail('◆', 'No GPO selected',
				'Select a GPO to inspect its settings, links and permissions.'));
			return;
		}
		if (tab === 'settings') return renderSettingTab();
		if (tab === 'overview') return renderOverviewTab();
		if (tab === 'links') return renderLinksTab();
		if (tab === 'permissions') return renderPermsTab();
	}
	function kvGrid(rows) {
		const kv = h('div.kv-grid');
		rows.forEach(r => kv.append(h('div.k', r[0]),
			h('div', { class: 'v ' + (r[2] || '') }, r[1] == null || r[1] === '' ? '—' : String(r[1]))));
		return kv;
	}
	function renderSettingTab() {
		const c = settingsCache[selGpo.guid];
		if (!c) { detailHost.appendChild(h('div.empty', h('div.spinner'))); return; }
		if (!selLeaf) {
			detailHost.appendChild(emptyDetail('⚙', 'Select a setting from the tree',
				'Risky settings are flagged with ⚠ and highlighted in red.'));
			return;
		}
		const l = selLeaf;
		const path = h('div.path');
		l.path.forEach((p, i) => { if (i) path.appendChild(h('span.sep', '/')); path.append(p); });
		const rows = [];
		if (l.props) Object.keys(l.props).forEach(k =>
			rows.push([k, l.props[k], /cpassword/i.test(k) ? 'red' : '']));
		else rows.push(['value', l.value, l.finding ? 'red' : '']);
		rows.push(['source GPO', selGpo.name, '']);
		rows.push(['last modified', selGpo.modified, 'dim']);
		detailHost.appendChild(h('div.body',
			h('div.gpo-setting-head',
				h('div.name', l.name), path,
				h('div.pills', l.finding ? tag('⚠ risky', 'red') : tag('configured', 'green'))),
			kvGrid(rows),
			l.finding ? h('div.gpo-finding-box',
				h('div.head', '⚠ Security Finding — ' + (l.finding.label || l.finding.id)),
				l.finding.title) : null));
	}
	function renderOverviewTab() {
		const g = selGpo, a = g.attrs, s = gpoState(g.flags);
		const c = settingsCache[g.guid];
		const wql = attr(a, 'gPCWQLFilter');
		/* securityFilter is resolved server-side (Apply-Group-Policy ACEs) */
		const secFilter = Array.isArray(a.securityFilter) ? a.securityFilter : null;
		const rows = [
			['guid', g.guid, ''],
			['links', g.linkCount + ' SOM' + (g.linkCount === 1 ? '' : 's'), ''],
			['security filter', secFilter == null ? '(not resolved)'
				: (secFilter.length ? secFilter.join(', ') : '(none — GPO applies to no principal)'),
				secFilter && !secFilter.length ? 'yellow' : ''],
			['settings', c && !c.error ? c.count + ' defined' : '(SYSVOL scan pending)', 'dim'],
			['version', g.version, 'dim'],
			['functionality version', attr(a, 'gPCFunctionalityVersion'), 'dim'],
			['created', g.created, 'dim'],
			['modified', g.modified, 'dim'],
			['sysvol path', g.path, ''],
			['machine extensions', attr(a, 'gPCMachineExtensionNames'), 'dim'],
			['user extensions', attr(a, 'gPCUserExtensionNames'), 'dim']
		];
		if (wql) rows.splice(9, 0, ['wmi filter', wql, '']);
		const findings = [];
		(g.findings || []).forEach(f => findings.push({
			head: f.label || f.id, sub: '', body: f.title || '' }));
		if (c && !c.error) c.findings.forEach(l => findings.push({
			head: l.finding.label || l.finding.id,
			sub: l.path.join(' / ') + ' / ' + l.name, body: l.finding.title }));
		const body = h('div.body',
			h('div.gpo-setting-head',
				h('div.name', g.name),
				h('div.path', g.guid),
				h('div.pills',
					tag(s[0] === 'off' ? 'disabled' : s[0] === 'partial' ? 'partial' : 'enabled', s[1]),
					g.findings.map(f => tag(f.label || f.id, gpoFindingTagColor(f.severity))))),
			kvGrid(rows));
		if (findings.length) {
			body.appendChild(h('div', { style: { marginTop: '18px', marginBottom: '6px',
				color: 'var(--muted)', fontSize: '10.5px', textTransform: 'uppercase',
				letterSpacing: '0.06em', fontWeight: '600' } },
				'Security Findings (' + findings.length + ')'));
			findings.forEach(f => body.appendChild(h('div.gpo-finding-box',
				h('div.head', '⚠ ' + f.head),
				f.sub ? h('div', { style: { color: 'var(--muted)', fontSize: '11px',
					marginBottom: '4px' } }, f.sub) : null,
				f.body)));
		}
		detailHost.appendChild(body);
	}
	function renderLinksTab() {
		const body = h('div.body',
			h('div.gpo-link-row.head',
				h('span', 'OU / SOM'), h('span', 'ORDER'), h('span', 'ENFORCED'), h('span', 'STATE')));
		if (!selGpo.links.length)
			body.appendChild(h('div', { style: { padding: '24px 0', color: 'var(--muted)',
				textAlign: 'center' } }, 'This GPO is not linked to any container.'));
		selGpo.links.forEach(l => body.appendChild(h('div.gpo-link-row',
			h('span.dn', { title: l.som }, somLabel(l.som),
				h('span.xs.muted', { style: { marginLeft: '5px' } }, '(' + l.somType + ')')),
			h('span.ord', '#' + l.order),
			h('span', l.enforced ? tag('enforced', 'yellow') : tag('—', 'gray')),
			h('span', l.enabled ? tag('enabled', 'green') : tag('disabled', 'gray')))));
		detailHost.appendChild(body);
	}
	async function loadAcl(g) {
		if (aclCache[g.dn]) { if (selGpo === g && tab === 'permissions') renderDetail(); return; }
		try {
			const data = await api.op('get', 'domainobjectacl', { identity: g.dn });
			const list = Array.isArray(data) ? data : (data ? [data] : []);
			const aces = [];
			list.forEach(e => {
				const at = e && e.attributes;
				if (Array.isArray(at)) aces.push.apply(aces, at);
				else if (at) aces.push(at);
			});
			aclCache[g.dn] = aces;
		} catch (e) { aclCache[g.dn] = { error: e.message }; }
		if (selGpo === g && tab === 'permissions') renderDetail();
	}
	function renderPermsTab() {
		const c = aclCache[selGpo.dn];
		if (!c) { detailHost.appendChild(h('div.empty', h('div.spinner'))); return; }
		if (c.error) {
			detailHost.appendChild(emptyDetail('∅', 'ACL read failed', c.error));
			return;
		}
		const body = h('div.body',
			h('div.gpo-perm-row.head',
				h('span', 'TRUSTEE'), h('span', 'RIGHT'), h('span', 'TYPE')));
		if (!c.length)
			body.appendChild(h('div', { style: { padding: '24px 0', color: 'var(--muted)',
				textAlign: 'center' } }, 'No ACEs returned for this GPO object.'));
		c.forEach(ace => {
			const who = ace.SecurityIdentifier || ace.ObjectSID || '—';
			const right = ace.ObjectAceType || ace.ActiveDirectoryRights || ace.AccessMask || '—';
			const deny = /DENIED/i.test(ace.ACEType || '');
			const inherited = /INHERITED_ACE/i.test(ace.ACEFlags || '');
			/* a non-admin holding a write/control right on the GPO = edit-as-codeexec */
			const danger = /GenericAll|WriteDacl|WriteOwner|WriteProperty|AllExtendedRights|Self/i.test(right)
				&& !/admin|system|enterprise|creator owner/i.test(String(who));
			body.appendChild(h('div.gpo-perm-row',
				h('span', { class: 'who' + (danger ? ' danger' : '') }, String(who)),
				h('span', { style: { color: deny ? 'var(--red)' : 'var(--text-2)' } },
					(deny ? 'DENY · ' : '') + right),
				h('span', inherited ? tag('↑ inherited', 'blue') : tag('direct', 'gray'))));
		});
		detailHost.appendChild(body);
	}

	async function load() {
		selGpo = null; selLeaf = null;
		Object.keys(settingsCache).forEach(k => delete settingsCache[k]);
		Object.keys(aclCache).forEach(k => delete aclCache[k]);
		clear(listHost);
		const done = withSpinner(listHost);
		try {
			const data = await api.op('get', 'domaingpo',
				{ properties: ['*'], resolve_links: true, resolve_security_filter: true });
			done();
			gpos = (Array.isArray(data) ? data : []).map(gpoRow)
				.sort((x, y) => x.name.toLowerCase().localeCompare(y.name.toLowerCase()));
			renderList();
			const first = gpos.find(g => g.findings.length) || gpos[0];
			if (first) selectGpo(first);
			else { renderTabs(); renderTree(); renderDetail(); }
		} catch (e) { done(); clear(listHost); listHost.appendChild(h('div.empty', e.message)); }
	}
	renderTabs(); renderTree(); renderDetail();
	load();
};

})();
