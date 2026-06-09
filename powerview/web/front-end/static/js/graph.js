/* powerview.py web ui — Graph (interactive relationship / attack-path view)
   Seeds from ?identity= (or the domain's privileged groups), and expands a
   node's memberships + delegation edges on click. Force-directed layout. */
(function () {
"use strict";
const { h, $, clear, api, attr, uacFlags, btn, toast, withSpinner } = window.PV;
const SVGNS = 'http://www.w3.org/2000/svg';
function s(tag, attrs, ...kids) {
	const el = document.createElementNS(SVGNS, tag);
	for (const k in (attrs || {})) el.setAttribute(k, attrs[k]);
	kids.forEach(c => c != null && el.appendChild(c.nodeType ? c : document.createTextNode(String(c))));
	return el;
}
const PRIV_GROUPS = ['Domain Admins', 'Enterprise Admins', 'Administrators',
	'Backup Operators', 'Account Operators', 'Server Operators', 'DnsAdmins'];
const MEMBER_CAP = 24;            /* nodes added per group expansion */
const CX = 500, CY = 320;

function classesOf(a) {
	let oc = (a && a.objectClass) || [];
	if (!Array.isArray(oc)) oc = oc ? [oc] : [];
	return oc.map(x => String(x).toLowerCase());
}
function typeOfClasses(oc) {
	return oc.indexOf('computer') > -1 ? 'computer' : oc.indexOf('group') > -1 ? 'group'
		: oc.indexOf('user') > -1 ? 'user' : 'user';
}
/* an identity can match several LDAP objects (e.g. a computer plus its
   msDFSR-Member shadow); pick the real principal, not the noise */
function pickEntry(r) {
	const list = Array.isArray(r) ? r : (r ? [r] : []);
	if (!list.length) return {};
	const score = e => {
		const a = (e && e.attributes) || {};
		const oc = classesOf(a);
		let sc = oc.indexOf('computer') > -1 ? 4 : oc.indexOf('group') > -1 ? 3 : oc.indexOf('user') > -1 ? 2 : 0;
		if (attr(a, 'sAMAccountName')) sc += 1;
		return sc;
	};
	return list.slice().sort((x, y) => score(y) - score(x))[0] || list[0];
}
function cnOf(dn) { const m = String(dn || '').match(/CN=([^,]+)/i); return m ? m[1] : String(dn || ''); }
function hostOfSpn(spn) { return String(spn || '').split('/')[1] ? String(spn).split('/')[1].split(':')[0] : ''; }

window.PV.pages.graph = function () {
	const main = $('#main');
	const wrap = h('div.graph-wrap');
	const pathBar = h('div.path-bar', h('span.muted', 'PATH'),
		h('span', 'select a node — click to expand its memberships & delegation'));
	main.append(
		h('div.page-head', h('span.title', 'Graph'), h('span.crumbs', '/ membership & delegation'),
			h('span.grow'), h('div.toolbar',
				btn('⟲ Rebuild', null, () => seed()),
				btn('Fit', null, () => { fitView(); apply(); }),
				btn('Reset view', null, () => { view = { x: 0, y: 0, k: 1 }; apply(); }))),
		wrap);

	const root = s('g');
	const edgesG = s('g'), nodesG = s('g');
	root.append(edgesG, nodesG);
	const svg = s('svg', { viewBox: '0 0 1000 640' }, root);
	wrap.append(svg,
		h('div.graph-overlay',
			h('div.h', 'Legend'),
			legendRow('#e06c75', 'Domain'), legendRow('#e6c07a', 'Group'),
			legendRow('#7aa2f7', 'User'), legendRow('#5fd1b3', 'Computer'),
			h('div.legend-row', h('span.swatch-line.member'), 'member of'),
			h('div.legend-row', h('span.swatch-line.deleg'), 'delegates to')),
		h('div.graph-zoom',
			h('button', { title: 'zoom in', onclick: () => zoom(1.25) }, '+'),
			h('button', { title: 'zoom out', onclick: () => zoom(0.8) }, '−'),
			h('button', { title: 'fit', onclick: () => { fitView(); apply(); } }, '⊙')),
		pathBar);

	let view = { x: 0, y: 0, k: 1 };
	function apply() { root.setAttribute('transform',
		'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')'); }
	function zoom(f) { view.k = Math.max(0.3, Math.min(3, view.k * f)); apply(); }
	function legendRow(color, label) {
		return h('div.legend-row', h('span.swatch', { style: { background: color } }), label);
	}

	/* pan + wheel zoom (teardown registered so listeners don't leak under the router) */
	let drag = null;
	svg.addEventListener('mousedown', e => { if (e.target === svg || e.target === root) drag = { x: e.clientX - view.x, y: e.clientY - view.y }; });
	const onMove = e => { if (!drag) return; view.x = e.clientX - drag.x; view.y = e.clientY - drag.y; apply(); };
	const onUp = () => { drag = null; };
	window.addEventListener('mousemove', onMove);
	window.addEventListener('mouseup', onUp);
	window.PV.onLeave(() => {
		window.removeEventListener('mousemove', onMove);
		window.removeEventListener('mouseup', onUp);
	});
	svg.addEventListener('wheel', e => { e.preventDefault(); zoom(e.deltaY < 0 ? 1.12 : 0.9); }, { passive: false });

	/* ── graph state ── */
	const nodes = new Map();          /* id -> {id,type,label,identity,x,y,pinned,expanded,deleg,_fx,_fy} */
	let edges = [];                   /* {from,to,kind}  kind: 'member' | 'deleg' */
	const edgeSet = new Set();
	let selId = null, busy = false;

	function addNode(id, type, label, identity, near) {
		id = String(id || '').toLowerCase();
		if (!id) return null;
		let n = nodes.get(id);
		if (n) return n;
		const jitter = () => (Math.random() - 0.5) * 60;
		n = { id: id, type: type, label: label || id, identity: identity || label || id,
			x: near ? near.x + jitter() : CX + jitter(), y: near ? near.y + jitter() : CY + jitter(),
			pinned: false, expanded: false, deleg: null };
		nodes.set(id, n);
		return n;
	}
	function addEdge(from, to, kind) {
		if (!from || !to || from === to) return;
		const key = from + '|' + to + '|' + kind;
		if (edgeSet.has(key)) return;
		edgeSet.add(key); edges.push({ from: from, to: to, kind: kind });
	}

	/* ── Fruchterman-Reingold-ish force layout ── */
	function layout(iters) {
		const arr = Array.from(nodes.values());
		if (arr.length < 2) return;
		const k = Math.max(60, Math.sqrt((900 * 560) / arr.length));
		let temp = 90;
		const cool = temp / (iters + 1);
		for (let it = 0; it < iters; it++) {
			for (const a of arr) { a._fx = 0; a._fy = 0; }
			for (let i = 0; i < arr.length; i++) {
				for (let j = i + 1; j < arr.length; j++) {
					const a = arr[i], b = arr[j];
					let dx = a.x - b.x, dy = a.y - b.y;
					let d = Math.hypot(dx, dy) || 0.01;
					const rep = (k * k) / d;
					const ux = dx / d * rep, uy = dy / d * rep;
					a._fx += ux; a._fy += uy; b._fx -= ux; b._fy -= uy;
				}
			}
			for (const e of edges) {
				const a = nodes.get(e.from), b = nodes.get(e.to);
				if (!a || !b) continue;
				let dx = a.x - b.x, dy = a.y - b.y;
				let d = Math.hypot(dx, dy) || 0.01;
				const att = (d * d) / k;
				const ux = dx / d * att, uy = dy / d * att;
				a._fx -= ux; a._fy -= uy; b._fx += ux; b._fy += uy;
			}
			for (const a of arr) {
				if (a.pinned) continue;
				let d = Math.hypot(a._fx, a._fy) || 0.01;
				const step = Math.min(d, temp) / d;
				a.x += a._fx * step; a.y += a._fy * step;
			}
			temp = Math.max(2, temp - cool);
		}
	}

	function fitView() {
		const arr = Array.from(nodes.values());
		if (!arr.length) { view = { x: 0, y: 0, k: 1 }; return; }
		let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
		arr.forEach(n => { minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
			minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y); });
		const pad = 70, w = (maxX - minX) + pad * 2, hh = (maxY - minY) + pad * 2;
		const k = Math.max(0.3, Math.min(1.4, Math.min(1000 / w, 640 / hh)));
		view.k = k;
		view.x = 500 - ((minX + maxX) / 2) * k;
		view.y = 320 - ((minY + maxY) / 2) * k;
	}

	/* ── render ── */
	function render() {
		clear(edgesG); clear(nodesG);
		edges.forEach(e => {
			const a = nodes.get(e.from), b = nodes.get(e.to);
			if (!a || !b) return;
			const sel = (selId && (e.from === selId || e.to === selId));
			edgesG.appendChild(s('line', { class: 'edge ' + e.kind + (sel ? ' sel' : ''),
				x1: a.x, y1: a.y, x2: b.x, y2: b.y }));
		});
		nodes.forEach(n => {
			const r = n.type === 'domain' ? 20 : n.type === 'group' ? 14 : n.type === 'more' ? 10 : 10;
			const cls = 'node-' + n.type + ' gnode' + (n.id === selId ? ' sel' : '') + (n.deleg ? ' deleg-flag' : '');
			const g = s('g', { class: cls, transform: 'translate(' + n.x + ',' + n.y + ')', style: 'cursor:pointer' });
			g.appendChild(s('circle', { r: r }));
			if (n.deleg) g.appendChild(s('circle', { class: 'deleg-ring', r: r + 3, fill: 'none' }));
			g.appendChild(s('text', { class: 'node-label', x: 0, y: r + 12, 'text-anchor': 'middle' }, n.label));
			g.addEventListener('click', ev => { ev.stopPropagation(); selectNode(n); });
			nodesG.appendChild(g);
		});
		apply();
	}

	/* ── path / selection bar ── */
	function setPath(n) {
		clear(pathBar);
		pathBar.appendChild(h('span.muted', 'PATH'));
		if (!n) { pathBar.appendChild(h('span', 'select a node')); return; }
		pathBar.appendChild(h('span.seg', n.type));
		pathBar.appendChild(h('span.edge', '→'));
		pathBar.appendChild(h('span.seg', n.label));
		if (n.deleg) { pathBar.appendChild(h('span.edge', '·')); pathBar.appendChild(h('span.seg.warn', n.deleg)); }
		const page = n.type === 'user' ? '/users' : n.type === 'computer' ? '/computers' : null;
		if (page)
			pathBar.appendChild(h('a.path-open', { href: '#',
				onclick: e => { e.preventDefault(); window.PV.navigate(page + '?identity=' + encodeURIComponent(n.identity)); } },
				'open in ' + (n.type === 'user' ? 'Users' : 'Computers') + ' →'));
		if (!n.expanded && n.type !== 'more')
			pathBar.appendChild(h('span.path-hint', '· click again to expand'));
	}

	function selectNode(n) {
		selId = n.id; setPath(n); render();
		if (!n.expanded && !busy) expand(n);
	}

	/* ── expansion ── */
	async function expand(n) {
		if (n.expanded || n.type === 'more') return;
		busy = true;
		const done = withSpinner(wrap);
		try {
			if (n.type === 'domain') await expandDomain(n);
			else if (n.type === 'group') await expandGroup(n);
			else await expandPrincipal(n);     /* user / computer / generic */
			n.expanded = true;
			layout(70); render();
			if (selId === n.id) setPath(n);     /* drop the "click to expand" hint, surface deleg */
		} catch (e) { toast('error', e.message); }
		finally { done(); busy = false; }
	}

	async function expandDomain(n) {
		for (const gname of PRIV_GROUPS) {
			try {
				const r = await api.op('get', 'domaingroup', { identity: gname, properties: ['sAMAccountName'] });
				if (r && r.length) {
					const g = addNode(gname, 'group', gname, gname, n);
					addEdge(g.id, n.id, 'member');
				}
			} catch (e) { /* group absent */ }
		}
	}

	async function expandGroup(n) {
		const mem = await api.op('get', 'domaingroupmember', { identity: n.identity });
		const all = mem || [];
		all.slice(0, MEMBER_CAP).forEach(m => {
			const a = m.attributes || {};
			const name = attr(a, 'MemberName') || attr(a, 'MemberSID') || '?';
			const sid = attr(a, 'MemberSID') || name;
			const mt = String(attr(a, 'MemberType') || '').toLowerCase();
			const type = mt.includes('computer') ? 'computer' : mt.includes('group') ? 'group' : 'user';
			const c = addNode(sid, type, name, name, n);
			addEdge(c.id, n.id, 'member');         /* member -> group */
		});
		const overflow = all.length - Math.min(all.length, MEMBER_CAP);
		if (overflow > 0) {
			const more = addNode(n.id + '|more', 'more', '+' + overflow + ' more', n.identity, n);
			more.expanded = true;
			addEdge(more.id, n.id, 'member');
		}
	}

	async function expandPrincipal(n) {
		const props = ['sAMAccountName', 'objectClass', 'distinguishedName', 'memberOf',
			'userAccountControl', 'msDS-AllowedToDelegateTo', 'dNSHostName'];
		const r = await api.op('get', 'domainobject', { identity: n.identity, properties: props });
		const a = pickEntry(r).attributes || {};
		/* group memberships */
		let mo = a.memberOf || [];
		if (!Array.isArray(mo)) mo = mo ? [mo] : [];
		mo.slice(0, MEMBER_CAP).forEach(dn => {
			const cn = cnOf(dn);
			const g = addNode(dn, 'group', cn, cn, n);
			addEdge(n.id, g.id, 'member');         /* this -> group */
		});
		/* delegation flags + constrained targets */
		const fl = uacFlags(a.userAccountControl);
		if (fl.includes('TRUSTED_FOR_DELEGATION')) n.deleg = 'unconstrained';
		else if (fl.includes('TRUSTED_TO_AUTH_FOR_DELEGATION')) n.deleg = 'constrained';
		let dts = a['msDS-AllowedToDelegateTo'] || [];
		if (!Array.isArray(dts)) dts = dts ? [dts] : [];
		if (dts.length && !n.deleg) n.deleg = 'constrained';
		const seenHosts = {};
		dts.forEach(spn => {
			const host = hostOfSpn(spn);
			if (!host || seenHosts[host.toLowerCase()]) return;
			seenHosts[host.toLowerCase()] = 1;
			const t = addNode(host, 'computer', host, host, n);
			addEdge(n.id, t.id, 'deleg');          /* this -> delegation target */
		});
	}

	/* ── seed ── */
	async function seed() {
		nodes.clear(); edges = []; edgeSet.clear(); selId = null; busy = false;
		clear(edgesG); clear(nodesG);
		const done = withSpinner(wrap);
		try {
			const info = await api.get('/api/get/domaininfo').catch(() => ({}));
			const domName = info.domain || info.flatName || 'domain';
			const identity = (window.PV.route && window.PV.route.params && window.PV.route.params.identity) || '';
			if (identity) {
				const r = await api.op('get', 'domainobject',
					{ identity: identity, properties: ['sAMAccountName', 'objectClass', 'name'] }).catch(() => null);
				const a = pickEntry(r).attributes || {};
				const type = typeOfClasses(classesOf(a));
				const label = attr(a, 'sAMAccountName') || attr(a, 'name') || identity;
				const n = addNode(label, type, label, label);
				n.x = CX; n.y = CY; n.pinned = true;
				done();
				selId = n.id; setPath(n); render();
				await expand(n); n.pinned = false; fitView(); apply();
				toast('info', 'seeded from ' + label);
				return;
			}
			/* default: domain root, expand to privileged groups */
			const d = addNode(domName, 'domain', domName, domName);
			d.x = CX; d.y = CY; d.pinned = true;
			done();
			render();
			await expand(d); d.pinned = false; layout(160); fitView(); apply();
		} catch (e) { done(); toast('error', e.message); }
	}

	svg.addEventListener('click', e => { if (e.target === svg) { selId = null; setPath(null); render(); } });
	seed();
};
})();
