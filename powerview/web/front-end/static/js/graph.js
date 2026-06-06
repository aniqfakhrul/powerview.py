/* powerview.py web ui — Graph (BloodHound-style relationship view) */
(function () {
"use strict";
const { h, $, clear, api, attr, btn, toast, withSpinner } = window.PV;
const SVGNS = 'http://www.w3.org/2000/svg';
function s(tag, attrs, ...kids) {
	const el = document.createElementNS(SVGNS, tag);
	for (const k in (attrs || {})) el.setAttribute(k, attrs[k]);
	kids.forEach(c => c != null && el.appendChild(c.nodeType ? c : document.createTextNode(String(c))));
	return el;
}

window.PV.pages.graph = function () {
	const main = $('#main');
	const wrap = h('div.graph-wrap');
	const pathBar = h('div.path-bar', h('span.muted', 'PATH'), h('span', 'select a node to trace membership'));
	main.append(
		h('div.page-head', h('span.title', 'Graph'), h('span.crumbs', '/ membership & delegation'),
			h('span.grow'), h('div.toolbar',
				btn('⟲ Rebuild', null, () => load()),
				btn('Reset view', null, () => { view = { x: 0, y: 0, k: 1 }; apply(); }))),
		wrap);

	const root = s('g');
	const svg = s('svg', { viewBox: '0 0 1000 640' }, root);
	wrap.append(svg,
		h('div.graph-overlay',
			h('div.h', 'Legend'),
			legendRow('#e06c75', 'Domain'),
			legendRow('#e6c07a', 'Group'),
			legendRow('#7aa2f7', 'User'),
			legendRow('#5fd1b3', 'Computer')),
		h('div.graph-zoom',
			h('button', { onclick: () => zoom(1.25) }, '+'),
			h('button', { onclick: () => zoom(0.8) }, '−'),
			h('button', { onclick: () => { view = { x: 0, y: 0, k: 1 }; apply(); } }, '⊙')),
		pathBar);

	let view = { x: 0, y: 0, k: 1 };
	function apply() { root.setAttribute('transform',
		'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')'); }
	function zoom(f) { view.k = Math.max(0.3, Math.min(3, view.k * f)); apply(); }
	function legendRow(color, label) {
		return h('div.legend-row', h('span.swatch', { style: { background: color } }), label);
	}

	/* pan + wheel zoom */
	let drag = null;
	svg.addEventListener('mousedown', e => { drag = { x: e.clientX - view.x, y: e.clientY - view.y }; });
	window.addEventListener('mousemove', e => {
		if (!drag) return; view.x = e.clientX - drag.x; view.y = e.clientY - drag.y; apply();
	});
	window.addEventListener('mouseup', () => { drag = null; });
	svg.addEventListener('wheel', e => { e.preventDefault(); zoom(e.deltaY < 0 ? 1.12 : 0.9); }, { passive: false });

	function nodeGroup(cls, x, y, r, label, onclick) {
		const g = s('g', { class: cls + ' gnode', transform: 'translate(' + x + ',' + y + ')',
			style: 'cursor:pointer' });
		g.appendChild(s('circle', { r: r }));
		g.appendChild(s('text', { class: 'node-label', x: 0, y: r + 12, 'text-anchor': 'middle' }, label));
		if (onclick) g.addEventListener('click', onclick);
		return g;
	}

	async function load() {
		clear(root); view = { x: 0, y: 0, k: 1 }; apply();
		const done = withSpinner(wrap);
		const CX = 500, CY = 300;
		try {
			const info = await api.get('/api/get/domaininfo').catch(() => ({}));
			const domName = info.domain || info.flatName || 'domain';
			const PRIV = ['Domain Admins', 'Enterprise Admins', 'Administrators'];
			const groups = [];
			for (const gname of PRIV) {
				try {
					const mem = await api.op('get', 'domaingroupmember', { identity: gname });
					const all = mem || [];
					groups.push({ name: gname, members: all.slice(0, 9), total: all.length });
				} catch (e) { /* group may not exist */ }
			}
			done();
			if (!groups.length) { root.appendChild(s('text', { x: CX, y: CY, 'text-anchor': 'middle',
				class: 'node-label' }, 'no privileged groups resolved')); return; }

			const edges = s('g'), nodes = s('g');
			root.append(edges, nodes);
			const GR = 200, gStep = (2 * Math.PI) / groups.length;
			groups.forEach((grp, gi) => {
				const ga = gi * gStep - Math.PI / 2;
				const gx = CX + Math.cos(ga) * GR, gy = CY + Math.sin(ga) * GR;
				edges.appendChild(s('line', { class: 'edge path', x1: CX, y1: CY, x2: gx, y2: gy }));
				const mStep = (2 * Math.PI) / Math.max(grp.members.length, 1);
				grp.members.forEach((m, mi) => {
					const a = m.attributes || {};
					const ma = ga + (mi - (grp.members.length - 1) / 2) * 0.34;
					const mx = gx + Math.cos(ma) * 110, my = gy + Math.sin(ma) * 110;
					const mtype = String(attr(a, 'MemberType') || '').toLowerCase().includes('computer')
						? 'node-comp' : 'node-user';
					edges.appendChild(s('line', { class: 'edge attack', x1: gx, y1: gy, x2: mx, y2: my }));
					nodes.appendChild(nodeGroup(mtype, mx, my, 9,
						attr(a, 'MemberName') || attr(a, 'MemberSID') || '?',
						() => setPath([domName, grp.name, attr(a, 'MemberName') || '?'])));
				});
				const overflow = grp.total - grp.members.length;
				if (overflow > 0) {
					const oi = grp.members.length;
					const oa = ga + (oi - (grp.members.length - 1) / 2) * 0.34;
					const ox = gx + Math.cos(oa) * 110, oy = gy + Math.sin(oa) * 110;
					edges.appendChild(s('line', { class: 'edge attack', x1: gx, y1: gy, x2: ox, y2: oy }));
					nodes.appendChild(nodeGroup('node-more', ox, oy, 9, '+' + overflow + ' more',
						() => setPath([domName, grp.name, '+' + overflow + ' more'])));
				}
				nodes.appendChild(nodeGroup('node-group', gx, gy, 15, grp.name,
					() => setPath([domName, grp.name])));
			});
			nodes.appendChild(nodeGroup('node-domain', CX, CY, 22, domName,
				() => setPath([domName])));
		} catch (e) { done(); toast('error', e.message); }
	}

	function setPath(segs) {
		clear(pathBar);
		pathBar.appendChild(h('span.muted', 'PATH'));
		segs.forEach((sg, i) => {
			if (i) pathBar.appendChild(h('span.edge', '→'));
			pathBar.appendChild(h('span.seg', sg));
		});
	}
	load();
};
})();
