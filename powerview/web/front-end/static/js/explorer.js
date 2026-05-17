/* powerview.py web ui — Explorer (ADSI-edit style tree + property grid) */
(function () {
"use strict";
const { h, $, clear, api, attr, fmtVal, uacFlags, objIcon, propsView, btn, toast, withSpinner } = window.PV;

function typeOf(oc) {
	const c = (Array.isArray(oc) ? oc.join(' ') : (oc || '')).toLowerCase();
	if (c.includes('computer')) return 'computer';
	if (c.includes('grouppolicycontainer')) return 'obj';
	if (c.includes('group')) return 'group';
	if (c.includes('organizationalunit')) return 'ou';
	if (c.includes('user')) return 'user';
	if (c.includes('domaindns') || c.includes('builtindomain')) return 'domain';
	if (c.includes('container') || c.includes('lostandfound') || c.includes('infrastructure')) return 'container';
	return 'obj';
}
const EXPANDABLE = { domain: 1, ou: 1, container: 1 };

window.PV.pages.explorer = async function () {
	const main = $('#main');
	const tree = h('div.tree');
	const propHost = h('div.props');
	const selLabel = h('span', 'Select an object');
	const selDn = h('span.muted.mono.xs');
	const crumb = h('span.crumbs');

	main.append(
		h('div.page-head',
			h('span.title', 'Explorer'), crumb, h('span.grow'),
			h('div.toolbar', btn('⟲ Refresh', null, () => load()))),
		h('div.split',
			h('div.pane.left',
				h('div.pane-head', h('span', 'Naming Contexts'), h('span.grow'), h('span.muted.mono.xs', 'LDAP')),
				tree),
			h('div.pane.fill',
				h('div.pane-head', selLabel, h('span', { style: { margin: '0 4px' } }, ' · '), selDn,
					h('span.grow'), h('span.muted.mono.xs', 'Object attributes')),
				propHost)));

	async function loadChildren(dn) {
		const data = await api.op('get', 'domainobject', {
			searchbase: dn, search_scope: 'LEVEL', raw: true,
			properties: ['name', 'objectClass', 'distinguishedName', 'sAMAccountName']
		});
		return (Array.isArray(data) ? data : []).map(e => {
			const a = e.attributes || {};
			const d = e.dn || attr(a, 'distinguishedName');
			/* some objects (TPM Devices, NTDS Quotas, Keys, …) return with name/
			   objectClass unreadable — fall back to the leading RDN, not the full DN */
			const rdn = d ? String(d).split(',')[0].replace(/^[^=]+=/, '') : d;
			return { dn: d, name: attr(a, 'name') || attr(a, 'sAMAccountName') || rdn, cls: a.objectClass };
		}).filter(n => n.dn).sort((x, y) => String(x.name).localeCompare(String(y.name)));
	}

	function nodeEl(node, depth, autoExpand) {
		const t = typeOf(node.cls);
		const expandable = !!EXPANDABLE[t];
		const kids = h('div.tnode-children');
		kids.hidden = true;
		let loaded = false, expanded = false;
		const twist = h('span.twist', expandable ? '▸' : '');
		const row = h('div.tree-node', { style: { paddingLeft: (4 + depth * 14) + 'px' } },
			twist, h('span', { class: 'ic t-' + t, html: objIcon(t) }), h('span.lbl', node.name),
			!expandable ? h('span.meta', t) : null);
		async function toggleExpand() {
			if (!expandable) return;
			expanded = !expanded;
			kids.hidden = !expanded;
			twist.textContent = expanded ? '▾' : '▸';
			if (expanded && !loaded) {
				loaded = true;
				twist.textContent = '·';
				try {
					const ch = await loadChildren(node.dn);
					ch.forEach(c => kids.appendChild(nodeEl(c, depth + 1)));
					if (!ch.length) kids.appendChild(h('div.tree-node',
						{ style: { paddingLeft: (4 + (depth + 1) * 14) + 'px', color: 'var(--dim)' } },
						h('span.twist'), h('span.ic'), h('span.lbl', '(empty)')));
				} catch (e) { toast('error', e.message); }
				twist.textContent = expanded ? '▾' : '▸';
			}
		}
		row.onclick = () => {
			$('.tree-node.selected', tree) && $('.tree-node.selected', tree).classList.remove('selected');
			row.classList.add('selected');
			selectObject(node);
			toggleExpand();
		};
		if (autoExpand) toggleExpand();
		return h('div', row, kids);
	}

	async function selectObject(node) {
		selLabel.textContent = node.name;
		selDn.textContent = node.dn;
		crumb.textContent = '/ ' + node.dn;
		clear(propHost);
		const done = withSpinner(propHost);
		try {
			/* BASE scope reads only the searchbase object itself, so the DN
			   must be passed as searchbase — passing it as `identity` alone
			   leaves searchbase defaulting to the root DN and matches nothing. */
			const data = await api.op('get', 'domainobject',
				{ searchbase: node.dn, properties: ['*'], search_scope: 'BASE', raw: true });
			const e = data && data[0];
			done();
			clear(propHost);
			if (!e) { propHost.appendChild(h('div.empty', 'object not found')); return; }
			renderProps(e.attributes || {});
		} catch (err) { done(); clear(propHost); propHost.appendChild(h('div.empty', err.message)); }
	}

	function renderProps(a) {
		const BUCKETS = {
			Identity: ['objectClass','cn','name','sAMAccountName','displayName','userPrincipalName',
				'distinguishedName','objectSid','objectGUID','description','sAMAccountType'],
			Account: ['userAccountControl','adminCount','pwdLastSet','lastLogon','lastLogonTimestamp',
				'logonCount','badPwdCount','accountExpires','primaryGroupID','lockoutTime'],
			'Kerberos / Delegation': ['servicePrincipalName','msDS-SupportedEncryptionTypes',
				'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity'],
			'Replication Metadata': ['whenCreated','whenChanged','uSNCreated','uSNChanged']
		};
		const used = new Set();
		const groups = [];
		/* userAccountControl is decoded server-side into flag-name strings, but
		   strip_entry collapses a single-flag list into a bare string — normalise
		   both shapes (and a raw integer) into a flag-name array. */
		const uacList = (v) => {
			if (v == null) return [];
			if (typeof v === 'string' && !/^\d+$/.test(v)) return [v];
			return uacFlags(v);
		};
		const colorFor = (k, v) => {
			if (k === 'userAccountControl') return uacList(v).includes('ACCOUNTDISABLE') ? 'red' : '';
			if (k === 'adminCount' && String(v) === '1') return 'yellow';
			if (k === 'servicePrincipalName') return 'yellow';
			if (k === 'sAMAccountName' || k === 'cn') return 'green';
			return '';
		};
		for (const title in BUCKETS) {
			const rows = [];
			BUCKETS[title].forEach(k => {
				if (a[k] == null) return;
				used.add(k);
				let val = fmtVal(a[k]);
				if (k === 'userAccountControl') {
					const fl = uacList(a[k]);
					val = fl.length ? fl.join(' | ') : fmtVal(a[k]);
				}
				rows.push({ k: k, v: val, cls: colorFor(k, a[k]) });
			});
			if (rows.length) groups.push({ title: title, rows: rows });
		}
		const mo = a.memberOf;
		if (mo) {
			used.add('memberOf');
			const list = Array.isArray(mo) ? mo : [mo];
			groups.push({ title: 'memberOf (' + list.length + ')',
				rows: list.map(g => ({ k: '', v: g })) });
		}
		const other = Object.keys(a).filter(k => !used.has(k)).sort();
		if (other.length) groups.push({ title: 'Other (' + other.length + ')', open: false,
			rows: other.map(k => ({ k: k, v: fmtVal(a[k]) })) });
		clear(propHost);
		propHost.appendChild(propsView(groups));
	}

	async function load() {
		clear(tree);
		const done = withSpinner(tree);
		let info;
		try {
			info = await api.get('/api/get/domaininfo');
		} catch (e) { done(); clear(tree); tree.appendChild(h('div.empty', e.message)); return; }
		/* RootDSE exposes every naming context (domain, Configuration, Schema,
		   DomainDnsZones, ForestDnsZones) via /api/server/info → raw.namingContexts */
		let ncs = [];
		try {
			const si = await api.get('/api/server/info');
			ncs = (si && si.raw && si.raw.namingContexts) || [];
			if (!Array.isArray(ncs)) ncs = [ncs];
		} catch (e) { /* fall back to the domain root only */ }
		done(); clear(tree);

		const rootDn = info.root_dn;
		const roots = ncs.length ? ncs.slice() : [rootDn];
		const sysDn = 'CN=System,' + rootDn;
		if (roots.indexOf(sysDn) < 0) roots.push(sysDn);

		roots.forEach(dn => {
			const isDomain = dn === rootDn;
			const label = isDomain
				? (info.domain || dn)
				: String(dn).split(',')[0].replace(/^[^=]+=/, '');
			/* auto-expand the domain naming context on page init */
			tree.appendChild(nodeEl({ dn: dn, name: label,
				cls: isDomain ? ['domainDNS'] : ['container'] }, 0, isDomain));
		});
	}
	load();
};
})();
