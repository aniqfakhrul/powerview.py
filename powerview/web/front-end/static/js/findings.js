/* powerview.py web ui — Findings (security findings catalog) */
(function () {
"use strict";
const { h, $, clear, add, api, tag, btn, toast } = window.PV;

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const SEV_COLOR = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue' };
const SEV_STAT = [
	['critical', 'red'], ['high', 'red'], ['medium', 'yellow'], ['low', 'blue']
];

function ago(iso) {
	const t = Date.parse(iso);
	if (isNaN(t)) return '';
	const s = Math.max(0, (Date.now() - t) / 1000);
	if (s < 60) return 'just now';
	if (s < 3600) return Math.floor(s / 60) + 'm ago';
	if (s < 86400) return Math.floor(s / 3600) + 'h ago';
	return Math.floor(s / 86400) + 'd ago';
}

window.PV.pages.findings = function () {
	const main = $('#main');
	let all = [], meta = {}, q = '', sevFilter = 'all', catFilter = 'all', selId = null;

	const crumb = h('span.crumbs');
	const searchInp = h('input', { placeholder: 'title, ID, category…',
		oninput: () => { q = searchInp.value; render(); } });
	const search = h('div.field', { style: { width: '220px' } }, h('span.glyph', '⌕'), searchInp);
	const rescanBtn = btn('⟲ Re-scan', null, () => load(true));

	const statsEl = h('div.findings-stats');
	const filterEl = h('div.findings-filter-bar');
	const tableHost = h('div.pane.fill');
	const detailHost = h('div.pane.right', { style: { width: '440px', background: 'var(--panel)' } });

	main.append(
		h('div.page-head', h('span.title', 'Findings'), crumb, h('span.grow'),
			h('div.toolbar', search, rescanBtn)),
		statsEl, filterEl,
		h('div.split', tableHost, detailHost));

	function load(refresh) {
		clear(tableHost); tableHost.appendChild(h('div.empty', h('div.spinner')));
		clear(statsEl); clear(filterEl); clear(detailHost);
		if (refresh) { rescanBtn.disabled = true; toast('info', 'rescanning findings…'); }
		api.get('/api/findings' + (refresh ? '?refresh=true' : '')).then(data => {
			rescanBtn.disabled = false;
			meta = data || {};
			/* the page shows real findings — checks that actually fired */
			all = ((data && data.findings) || []).filter(f => f.count > 0)
				.sort((a, b) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]));
			if (refresh) toast('success', 'scan complete — ' + all.length + ' finding(s)');
			selId = all.length ? all[0].id : null;
			render();
		}).catch(e => {
			rescanBtn.disabled = false;
			clear(tableHost); tableHost.appendChild(h('div.empty', e.message));
		});
	}

	function filtered() {
		const t = q.toLowerCase();
		return all.filter(f => {
			if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
			if (catFilter !== 'all' && f.category !== catFilter) return false;
			if (!t) return true;
			return (f.title || '').toLowerCase().includes(t)
				|| (f.code || '').toLowerCase().includes(t)
				|| (f.id || '').toLowerCase().includes(t)
				|| (f.category || '').toLowerCase().includes(t)
				|| (f.description || '').toLowerCase().includes(t);
		});
	}

	function render() {
		const view = filtered();
		crumb.textContent = '/ ' + view.length + ' of ' + all.length
			+ (meta.generated_at ? ' · scanned ' + ago(meta.generated_at) : '');
		renderStats();
		renderFilters();
		renderTable(view);
		const sel = all.find(f => f.id === selId) || view[0];
		renderDetail(sel);
	}

	function renderStats() {
		clear(statsEl);
		const sub = {
			critical: 'noPac · DCSync chains', high: 'roastable · delegation · ESC',
			medium: 'SMBv1 · MAQ · lockout', low: 'stale · DNS ACL'
		};
		SEV_STAT.forEach(([sev, color]) => {
			const n = all.filter(f => f.severity === sev).length;
			statsEl.appendChild(h('div', {
				class: 'findings-stat ' + color + (sevFilter === sev ? ' active' : ''),
				onclick: () => { sevFilter = sevFilter === sev ? 'all' : sev; render(); }
			},
				h('span.lbl', SEV_LABEL[sev]),
				h('span.num', String(n)),
				h('span.sub', sub[sev] || '')));
		});
	}

	function renderFilters() {
		clear(filterEl);
		const cats = {};
		all.forEach(f => { cats[f.category] = (cats[f.category] || 0) + 1; });
		const chip = (label, active, n, onclick) => h('span',
			{ class: 'findings-chip' + (active ? ' active' : ''), onclick: onclick },
			label, n != null ? h('span.count', String(n)) : null);
		const chips = h('div.chips',
			chip('All', catFilter === 'all', all.length, () => { catFilter = 'all'; render(); }));
		Object.keys(cats).sort().forEach(c => {
			chips.appendChild(chip(c, catFilter === c, cats[c],
				() => { catFilter = catFilter === c ? 'all' : c; render(); }));
		});
		filterEl.appendChild(h('span.findings-filter-label', 'Category'));
		filterEl.appendChild(chips);
	}

	function renderTable(view) {
		const rows = view.map(f => h('tr', {
			class: 'finding-row' + (f.id === selId ? ' selected' : ''),
			onclick: () => { selId = f.id; render(); }
		},
			h('td.sev-cell', h('span', { class: 'sev-' + f.severity },
				h('span.dot'), SEV_LABEL[f.severity] || f.severity)),
			h('td', { style: { color: 'var(--text-2)' } }, f.category || ''),
			h('td.id-cell', f.code || f.id),
			h('td.title-cell', { style: { whiteSpace: 'normal', maxWidth: 'none' } }, f.title || ''),
			h('td', { style: { color: 'var(--muted)' } }, f.subject || ''),
			h('td.scanned-cell', { title: f.scanned_at || '' },
				f.scanned_at ? ago(f.scanned_at) : '—')));
		const table = h('table.grid',
			h('thead', h('tr',
				h('th', { style: { width: '110px' } }, 'Severity'),
				h('th', { style: { width: '110px' } }, 'Category'),
				h('th', { style: { width: '110px' } }, 'ID'),
				h('th', 'Title'),
				h('th', { style: { width: '220px' } }, 'Source'),
				h('th', { style: { width: '120px' } }, 'Scanned'))),
			h('tbody', rows.length ? rows
				: [h('tr', h('td', { colspan: 6, style: { padding: '32px', textAlign: 'center',
					color: 'var(--muted)' } }, 'No findings match the current filters.'))]));
		clear(tableHost);
		tableHost.appendChild(h('div.table-wrap', table));
	}

	function section(title, body) {
		return h('div.fd-section', h('div.h', title), body);
	}

	function renderDetail(f) {
		clear(detailHost);
		if (!f) { detailHost.appendChild(h('div.empty', 'no finding selected')); return; }
		const d = h('div.finding-detail');
		d.appendChild(h('div.finding-detail-head',
			h('div.id-line', (f.code || f.id) + '  ·  ' + (f.category || '')),
			h('div.title', f.title || ''),
			h('div.pills',
				tag((SEV_LABEL[f.severity] || f.severity), SEV_COLOR[f.severity] || 'gray'),
				tag(f.category || ''),
				f.mode === 'active' ? tag('active', 'green') : null)));

		d.appendChild(section('Description',
			h('div.body', h('p', f.description || f.detail || ''))));

		if (f.evidence && f.evidence.length)
			d.appendChild(section('Evidence',
				h('div.body', f.evidence.map(e => h('p', e)))));

		const aff = f.affected || [];
		d.appendChild(section('Source / Affected',
			h('div.body',
				h('p', h('span.em', f.subject || (f.count + ' ' + (f.unit || '')))),
				f.scanned_at ? h('p.fd-scanned',
					'scanned ' + ago(f.scanned_at) + ' · ' + f.scanned_at.replace('T', ' ')) : null,
				aff.length ? h('div.fd-affected',
					aff.map(x => h('div.fd-affected-row', h('span.k', '·'), h('span.v', String(x))))) : null)));

		d.appendChild(section('Remediation',
			h('div.body', h('p', f.remediation || '—'))));

		if (f.commands && f.commands.length)
			d.appendChild(section('Commands',
				h('div', f.commands.map(c =>
					h('div.fd-cmd', h('span.prompt', '$'), c)))));

		if (f.references && f.references.length)
			d.appendChild(section('References',
				h('div.fd-refs', f.references.map(u =>
					h('a.fd-ref', { href: u, target: '_blank', rel: 'noreferrer' },
						h('span.glyph', '🔗'), u)))));

		detailHost.appendChild(d);
	}

	load(false);
};
})();
