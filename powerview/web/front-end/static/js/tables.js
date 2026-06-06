/* powerview.py web ui — table pages: Users, Computers, Groups
   + right-click context menus and action modals (Set-Password / Add-to-Group /
   Set-Owner / Delete) wired to the real write endpoints. */
(function () {
"use strict";
const { h, $, clear, api, attr, fmtVal, uacFlags, grid, tag, btn, propGroup, propRow,
        toast, runCmd, withSpinner, contextMenu, modal, showResultModal, inspectorPane } = window.PV;

/* ---- dedicated-endpoint enumerate actions ----
   Each calls a structured /api/{verb}/{method} route and shows the result
   array in a grid via showResultModal — no command-string re-parsing. */
const act = {
	getObject:   o => showResultModal('Get-DomainObject', o.sam || o.name,
		api.op('get', 'domainobject', { identity: o.sam || o.name, properties: ['*'], raw: true })),
	getAcl:      o => showResultModal('Get-DomainObjectAcl', o.sam || o.name,
		api.op('get', 'domainobjectacl', { identity: o.sam || o.name })),
	getSessions: c => showResultModal('Get-NetSession', c.name,
		api.op('get', 'netsession', { identity: c.name })),
	getLoggedOn: c => showResultModal('Get-NetLoggedOn', c.name,
		api.op('get', 'netloggedon', { computer_name: c.name })),
	getShares:   c => showResultModal('Get-NetShare', c.name,
		api.op('get', 'netshare', { args: { computer: c.name } })),
	kerberoast:  u => showResultModal('Invoke-Kerberoast', u.sam,
		api.op('invoke', 'kerberoast', { args: { identity: u.sam } })),
	asrepRoast:  u => showResultModal('Invoke-ASREPRoast', u.sam,
		api.op('invoke', 'asreproast', { args: { identity: u.sam } })),
	readLaps:    c => showResultModal('Read LAPS', c.name,
		api.op('get', 'domaincomputer', { args: { identity: c.name, laps: true } })),
	kerberoastAll: () => showResultModal('Invoke-Kerberoast', 'all SPN accounts',
		api.op('invoke', 'kerberoast', { args: {} }))
};

/* ---- helpers ---- */
function ouOf(dn) {
	if (!dn) return '';
	const ous = (dn.match(/OU=([^,]+)/gi) || []).map(x => x.slice(3));
	return ous.reverse().join('\\');
}
function ageDays(v) {
	const t = Date.parse(v);
	if (isNaN(t)) return null;
	return Math.floor((Date.now() - t) / 864e5);
}
/* render an LDAP timestamp as a coloured age counter — fresh (< 180d) neutral,
   stale (> 180d) yellow, very stale (> 365d) red; "never" for unset values.
   Needs raw timestamps (parseable GMT strings) — the table query sends raw:true. */
function daysCell(v) {
	if (v == null || v === '') return h('span.muted', '—');
	const t = Date.parse(v);
	if (isNaN(t)) return h('span.muted', { title: String(v) }, String(v));
	if (t <= 0) return h('span', { title: String(v), style: { color: 'var(--muted)' } }, 'never');
	const d = Math.floor((Date.now() - t) / 864e5);
	const txt = d <= 0 ? 'today' : d + 'd ago';
	const color = d > 365 ? 'var(--red)' : d > 180 ? 'var(--yellow)' : 'var(--text-2)';
	return h('span', { title: String(v), style: { color: color } }, txt);
}
function dateSort(v) { const t = Date.parse(v); return isNaN(t) ? 0 : t; }
const PRIV_GROUPS = ['domain admins', 'enterprise admins', 'schema admins', 'administrators',
	'account operators', 'backup operators', 'server operators', 'print operators',
	'dnsadmins', 'group policy creator owners'];

function field(label, control, help) {
	return h('div', h('div.lbl', label), control, help || null);
}

/* ============================ ACTION MODALS ============================ */
/* Each opens a compact modal with a PV› command echo, a form, and surfaces
   the real API result (or error) inline. */

/* Write endpoints (set/add/remove) return a boolean: the HTTP layer only
   raises a 4xx on an exception, so a logical failure (identity not found,
   access denied) comes back as a 200 with body `false`/`null`. Treat that
   as a failure instead of a false-positive success. */
function assertWriteOk(result, failMsg) {
	if (result === false || result === null || result === undefined)
		throw new Error(failMsg);
}

function setPasswordModal(u) {
	const pwd  = h('input', { type: 'password' });
	const pwd2 = h('input', { type: 'password' });
	const bar  = h('div.pwd-strength', h('div.seg'), h('div.seg'), h('div.seg'), h('div.seg'));
	const lbl  = h('div.pwd-strength-label', 'enter password');
	const mism = h('div.form-help', { style: { color: 'var(--red)' } }, "passwords don't match");
	mism.hidden = true;
	const result = h('div.form-result'); result.hidden = true;
	function recalc() {
		const p = pwd.value; let s = 0;
		if (p.length >= 8) s++;
		if (p.length >= 14) s++;
		if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
		if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++;
		bar.setAttribute('data-s', s);
		lbl.textContent = ['enter password', 'weak', 'fair', 'good', 'strong'][s];
		mism.hidden = !(pwd2.value && pwd.value !== pwd2.value);
	}
	pwd.oninput = recalc; pwd2.oninput = recalc;
	const body = h('div.form-stack',
		field('New password', pwd, h('div', bar, lbl)),
		field('Confirm', pwd2, mism),
		h('div.form-help', { html: 'Replaces <span class="em">unicodePwd</span> via LDAP modify over LDAPS.'
			+ (u.admin ? ' <span style="color:var(--red)">Target is AdminSDHolder-protected</span> — ACLs re-stamp within ~60 min.' : '') }),
		result);
	const m = modal({ cmd: 'Set-DomainUserPassword', subject: u.sam, width: 460, body: body });
	const submit = btn('Set password', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		recalc();
		if (!pwd.value || pwd.value !== pwd2.value) { toast('error', 'enter and confirm a password'); return; }
		submit.disabled = true; submit.textContent = 'Setting…';
		try {
			const r = await api.op('set', 'domainuserpassword', { identity: u.sam, accountpassword: pwd.value });
			assertWriteOk(r, 'Password reset failed for ' + u.sam + ' (account not found or access denied)');
			pwd.disabled = pwd2.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = '[+] Password reset for ' + u.sam;
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Set password';
		}
	}
}

function addToGroupModal(u, onDone) {
	const grpDl = h('datalist', { id: 'pv-group-list' });
	const grp = h('input', { placeholder: 'group sAMAccountName or DN — type or pick',
		list: 'pv-group-list', autocomplete: 'off', spellcheck: 'false' });
	/* auto-populate the picker with every domain group's sAMAccountName */
	groupSuggestions().then(opts => opts.forEach(s => grpDl.appendChild(h('option', { value: s }))));
	const warn = h('div.form-warn',
		{ html: '⚠  <strong>Privileged group.</strong> This creates a new edge to protected resources — DC event 4728.' });
	warn.hidden = true;
	const result = h('div.form-result'); result.hidden = true;
	grp.oninput = () => { warn.hidden = PRIV_GROUPS.indexOf(grp.value.trim().toLowerCase()) < 0; };
	const body = h('div.form-stack',
		field('Target group', grp, grpDl),
		warn,
		h('div.form-help', { html: 'Writes the <span class="em">member</span> attribute on the group; '
			+ 'effective at the DC immediately.' }),
		result);
	const m = modal({ cmd: 'Add-DomainGroupMember', subject: u.sam, width: 480, body: body });
	const submit = btn('Add member', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		const g = grp.value.trim();
		if (!g) { toast('error', 'enter a target group'); return; }
		submit.disabled = true; submit.textContent = 'Adding…';
		try {
			const r = await api.op('add', 'domaingroupmember', { identity: g, members: u.sam });
			assertWriteOk(r, "Failed to add '" + u.sam + "' to '" + g + "' (group/member not found or access denied)");
			grp.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] Added '" + u.sam + "' to '" + g + "'";
			if (onDone) onDone(g);   /* let the inspector refresh its memberOf panel */
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Add member';
		}
	}
}

/* reverse of addToGroupModal — from a group, add a member (user/principal). */
function addGroupMemberModal(g, onDone) {
	const memDl = h('datalist', { id: 'pv-member-list' });
	const mem = h('input', { placeholder: 'user sAMAccountName or DN — type or pick',
		list: 'pv-member-list', autocomplete: 'off', spellcheck: 'false' });
	/* auto-populate the picker with every domain user's sAMAccountName */
	userSuggestions().then(opts => opts.forEach(s => memDl.appendChild(h('option', { value: s }))));
	const priv = g.builtin || PRIV_GROUPS.indexOf((g.name || '').trim().toLowerCase()) > -1;
	const warn = h('div.form-warn',
		{ html: '⚠  <strong>Privileged group.</strong> Adding a member grants it access to protected resources — DC event 4728.' });
	warn.hidden = !priv;
	const result = h('div.form-result'); result.hidden = true;
	const body = h('div.form-stack',
		field('Group', h('input', { value: g.name, readonly: 'readonly', style: { color: 'var(--muted)' } })),
		field('Member to add', mem, memDl),
		warn,
		h('div.form-help', 'Writes the ', h('span.em', 'member'), ' attribute on ',
			h('span.em', g.name || 'the group'), '; effective at the DC immediately.'),
		result);
	const m = modal({ cmd: 'Add-DomainGroupMember', subject: g.name, width: 480, body: body });
	const submit = btn('Add member', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		const member = mem.value.trim();
		if (!member) { toast('error', 'enter a member to add'); return; }
		submit.disabled = true; submit.textContent = 'Adding…';
		try {
			const r = await api.op('add', 'domaingroupmember', { identity: g.dn || g.name, members: member });
			assertWriteOk(r, "Failed to add '" + member + "' to '" + g.name + "' (member/group not found or access denied)");
			mem.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] Added '" + member + "' to '" + g.name + "'";
			if (onDone) onDone();   /* let the inspector reload its Members panel */
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Add member';
		}
	}
}

/* confirm + remove a single member from a group (Remove-DomainGroupMember). */
function removeGroupMemberModal(g, memberLabel, memberId, onDone) {
	const result = h('div.form-result'); result.hidden = true;
	const body = h('div.form-stack',
		h('div.form-warn', 'Remove ',
			h('span', { style: { color: 'var(--red)', fontWeight: '600' } }, memberLabel),
			' from ', h('span.em', g.name || 'the group'), '?'),
		h('div.form-help', { html: "Clears the principal from the group's <span class=\"em\">member</span> "
			+ 'attribute (DC event 4729). The member object itself is not deleted.' }),
		result);
	const m = modal({ cmd: 'Remove-DomainGroupMember', subject: g.name, width: 460, body: body });
	const submit = btn('Remove member', 'danger', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		submit.disabled = true; submit.textContent = 'Removing…';
		try {
			const r = await api.op('remove', 'domaingroupmember', { identity: g.dn || g.name, members: memberId });
			assertWriteOk(r, "Failed to remove '" + memberLabel + "' from '" + g.name + "' (not found or access denied)");
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] Removed '" + memberLabel + "' from '" + g.name + "'";
			if (onDone) onDone();   /* refresh the inspector's Members panel */
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Remove member';
		}
	}
}

function setOwnerModal(obj, kind) {
	const name = obj.sam || obj.name;
	const target = obj.dn || name;
	const owner = h('input', { placeholder: 'sAMAccountName, SID, or DN' });
	const result = h('div.form-result'); result.hidden = true;
	const body = h('div.form-stack',
		field('Target DN', h('input', { value: target, readonly: 'readonly', style: { color: 'var(--muted)' } })),
		field('New owner', owner),
		h('div.form-help', { html: 'The owner of an object implicitly holds <span class="em">WriteDacl</span> '
			+ '— a common persistence primitive (also audit event 5136).' }),
		result);
	const m = modal({ cmd: 'Set-DomainObjectOwner', subject: name, width: 480, body: body });
	const submit = btn('Set owner', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		const o = owner.value.trim();
		if (!o) { toast('error', 'enter a new owner'); return; }
		submit.disabled = true; submit.textContent = 'Setting…';
		try {
			const r = await api.op('set', 'domainobjectowner', { targetidentity: target, principalidentity: o });
			assertWriteOk(r, "Failed to set owner of '" + name + "' (target/principal not found or access denied)");
			owner.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] Owner of '" + name + "' set to '" + o + "'";
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Set owner';
		}
	}
}

function deleteObjectModal(obj, kind, onDone) {
	const name = obj.sam || obj.name;
	const confirm = h('input', { placeholder: name });
	const result = h('div.form-result'); result.hidden = true;
	const submit = btn('Delete ' + kind, 'danger', doSubmit);
	submit.disabled = true;
	confirm.oninput = () => { submit.disabled = confirm.value !== name; };
	const body = h('div.form-stack',
		h('div.form-warn', { html: '⚠  Irreversible from the UI. The object is moved to '
			+ '<span style="color:var(--red);font-weight:600">CN=Deleted Objects</span> and tombstoned.' }),
		field(h('span', 'Type ', h('span', { style: { color: 'var(--accent)' } }, name), ' to confirm'), confirm),
		result);
	const m = modal({ cmd: kind === 'user' ? 'Remove-DomainUser' : 'Remove-DomainComputer',
		subject: name, width: 460, body: body });
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		if (confirm.value !== name) return;
		submit.disabled = true; submit.textContent = 'Deleting…';
		try {
			const r = kind === 'user'
				? await api.op('remove', 'domainuser', { identity: obj.dn || name })
				: await api.op('remove', 'domaincomputer', { computer_name: obj.dn || name });
			assertWriteOk(r, "Failed to remove '" + name + "' (object not found or access denied)");
			confirm.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] '" + name + "' removed";
			if (onDone) onDone();   /* drop the row from the table behind the modal */
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Delete ' + kind;
		}
	}
}

/* ---- Set-DomainObject attribute editor ----
   Generic LDAP attribute editor: lists the object's attributes, supports
   per-attribute edit / clear / add, and commits each pending change as a
   separate Set-DomainObject call (the endpoint takes one operation each). */
const READONLY_ATTRS = new Set(['distinguishedname', 'objectclass', 'objectsid', 'objectguid',
	'objectcategory', 'whencreated', 'whenchanged', 'usncreated', 'usnchanged',
	'samaccounttype', 'primarygroupid', 'instancetype', 'dscorepropagationdata']);
function isReadonlyAttr(k) { return READONLY_ATTRS.has(String(k).toLowerCase()); }

async function editAttributesModal(obj) {
	const name = obj.sam || obj.name;
	const identity = obj.dn || name;
	const body = h('div.form-stack', h('div.empty', h('div.spinner')));
	const m = modal({ cmd: 'Set-DomainObject', subject: name, width: 760, body: body });
	m.setFooter(btn('Cancel', null, m.close));

	const attrs = {};              /* attribute name -> current value (display string) */
	const multiValued = new Set(); /* attrs holding 2+ values — not inline-editable (a single
	                                  edit would replace the whole value list with one string) */
	try {
		const data = await api.op('get', 'domainobject', { identity: identity, properties: ['*'], raw: true });
		const entry = Array.isArray(data) ? data[0] : data;
		if (!entry || !entry.attributes) throw new Error('object not found: ' + name);
		const a = entry.attributes;
		Object.keys(a).forEach(k => {
			const v = a[k];
			if (Array.isArray(v) && v.length > 1) multiValued.add(k);
			attrs[k] = Array.isArray(v) ? v.join(', ') : (v == null ? '' : String(v));
		});
	} catch (e) {
		clear(body); body.appendChild(h('div.form-result.err', '[-] ' + e.message));
		m.setFooter(btn('Close', 'primary', m.close));
		return;
	}

	const edits = {};   /* key -> {type:'set'|'clear', value}  ;  '+name' -> {type:'add', key, value} */
	let filter = '', editing = null, editVal = '', adding = false, applied = false, resultEl = null;
	const applyBtn = btn('Apply', 'primary', apply);

	function counts() {
		const v = Object.values(edits);
		const set = v.filter(o => o.type === 'set').length;
		const clr = v.filter(o => o.type === 'clear').length;
		const add = v.filter(o => o.type === 'add').length;
		return { set: set, clear: clr, add: add, total: set + clr + add };
	}
	function commitEdit() {
		if (editing == null) return;
		const k = editing;
		if (editVal === (attrs[k] || '')) delete edits[k];
		else edits[k] = { type: 'set', value: editVal };
		editing = null; rebuild();
	}
	function doAdd(k, v) {
		k = (k || '').trim(); v = (v || '').trim();
		if (!k || !v) { toast('error', 'enter an attribute name and value'); return; }
		edits['+' + k] = { type: 'add', key: k, value: v };
		adding = false; rebuild();
	}
	function attrRow(k) {
		const op = edits[k], ro = isReadonlyAttr(k), multi = multiValued.has(k), isEd = editing === k;
		const row = h('div', { class: 'attr-row' + (op && op.type === 'set' ? ' edited'
			: op && op.type === 'clear' ? ' cleared' : '') + (ro ? ' readonly' : '') },
			h('div.attr-name', k));
		let valCell;
		if (isEd) {
			const inp = h('input', { value: editVal, oninput: e => editVal = e.target.value,
				onkeydown: e => { if (e.key === 'Enter') commitEdit(); if (e.key === 'Escape') { editing = null; rebuild(); } } });
			valCell = h('div.attr-val', inp);
			setTimeout(() => { inp.focus(); inp.select(); }, 0);
		} else if (op && op.type === 'clear') {
			valCell = h('div.attr-val', h('span.strike', attrs[k] || '(empty)'), h('span.cleared-mark', '→ (cleared)'));
		} else if (op && op.type === 'set') {
			valCell = h('div.attr-val', h('span.strike', attrs[k] || '(empty)'),
				h('span.arrow', '→'), h('span.new-val', op.value || '(empty)'));
		} else {
			valCell = h('div.attr-val', attrs[k] ? h('span', attrs[k]) : h('span.placeholder', '(not set)'),
				multi ? h('span.attr-multi', 'multi-valued') : null);
		}
		row.appendChild(valCell);
		const acts = h('div.attr-actions');
		if (op) acts.appendChild(h('button.attr-action', { title: 'revert',
			onclick: () => { delete edits[k]; rebuild(); } }, '⟲'));
		else acts.appendChild(h('button.attr-action', {
			title: multi ? 'multi-valued — edit via CLI to avoid corrupting the value list' : 'edit',
			disabled: ro || multi || applied,
			onclick: () => { editing = k; editVal = attrs[k] || ''; rebuild(); } }, '✎'));
		acts.appendChild(h('button.attr-action.danger', { title: 'clear', disabled: ro || !attrs[k] || applied,
			onclick: () => {
				if (edits[k] && edits[k].type === 'clear') delete edits[k];
				else edits[k] = { type: 'clear' };
				rebuild();
			} }, '✕'));
		row.appendChild(acts);
		return row;
	}
	function rebuild() {
		const c = counts();
		const list = h('div.attr-list');
		list.appendChild(h('div.filter-bar',
			h('span.mono.muted', '⌕'),
			h('input', { value: filter, placeholder: 'filter attribute name or value…',
				oninput: e => { filter = e.target.value; rebuild(); } }),
			h('button.btn', { disabled: adding || applied, onclick: () => { adding = true; rebuild(); } }, '+ Add attribute')));

		if (adding) {
			const kIn = h('input', { placeholder: 'attribute name' });
			const vIn = h('input', { placeholder: 'value',
				onkeydown: e => { if (e.key === 'Enter') doAdd(kIn.value, vIn.value); } });
			list.appendChild(h('div.attr-row.added',
				h('div.attr-name', kIn), h('div.attr-val', vIn),
				h('div.attr-actions',
					h('button.attr-action', { title: 'add', onclick: () => doAdd(kIn.value, vIn.value) }, '✓'),
					h('button.attr-action', { title: 'cancel', onclick: () => { adding = false; rebuild(); } }, '✕'))));
			setTimeout(() => kIn.focus(), 0);
		}
		Object.keys(edits).forEach(ek => {
			const op = edits[ek];
			if (op.type !== 'add') return;
			list.appendChild(h('div.attr-row.added',
				h('div.attr-name', op.key, ' ', h('span.muted', '(new)')),
				h('div.attr-val', h('span.new-val', op.value)),
				h('div.attr-actions', h('button.attr-action.danger', { title: 'remove',
					onclick: () => { delete edits[ek]; rebuild(); } }, '✕'))));
		});
		const f = filter.toLowerCase();
		const keys = Object.keys(attrs).filter(k => !f
			|| k.toLowerCase().indexOf(f) > -1 || attrs[k].toLowerCase().indexOf(f) > -1).sort();
		keys.forEach(k => list.appendChild(attrRow(k)));
		if (!keys.length) list.appendChild(h('div.attr-empty', '(no attributes match)'));

		const preview = h('div.attr-modify-preview');
		const lines = [];
		Object.keys(edits).forEach(ek => {
			const op = edits[ek];
			if (op.type === 'set') lines.push(['op-rep', 'REPLACE', ek, op.value]);
			else if (op.type === 'clear') lines.push(['op-del', 'DELETE', ek, null]);
			else if (op.type === 'add') lines.push(['op-add', 'ADD', op.key, op.value]);
		});
		if (!lines.length) preview.appendChild(h('span.muted', 'no pending changes'));
		else lines.forEach(l => preview.appendChild(h('div', { class: 'op-line ' + l[0] },
			l[1] + '  ', h('span.attr-key', l[2]),
			l[3] != null ? h('span', ' = ', h('span.attr-str', '"' + l[3] + '"')) : null)));

		clear(body);
		body.append(list, preview, h('div.form-help',
			'Each change commits a separate ', h('span.em', 'Set-DomainObject'), ' LDAP modify against ',
			h('span.em', identity), ". Read-only / system attributes can't be edited here."));
		if (resultEl) body.appendChild(resultEl);

		if (applied) { m.setFooter(btn('Done', 'primary', m.close)); return; }
		const summary = h('div.attr-summary');
		if (c.set) summary.appendChild(h('span.pill.y', c.set + ' replace'));
		if (c.clear) summary.appendChild(h('span.pill.r', c.clear + ' delete'));
		if (c.add) summary.appendChild(h('span.pill.g', c.add + ' add'));
		if (!c.total) summary.appendChild(h('span.muted', 'no pending changes'));
		applyBtn.disabled = !c.total;
		applyBtn.textContent = c.total ? 'Apply ' + c.total + ' change' + (c.total === 1 ? '' : 's') : 'Apply';
		m.setFooter([summary,
			btn('Discard', null, () => { Object.keys(edits).forEach(k => delete edits[k]); rebuild(); }),
			btn('Cancel', null, m.close), applyBtn]);
	}
	async function apply() {
		const ops = [];
		Object.keys(edits).forEach(ek => {
			const op = edits[ek];
			if (op.type === 'set') ops.push({ label: ek, params: { identity: identity, _set: { attribute: ek, value: [op.value] } } });
			else if (op.type === 'clear') ops.push({ label: ek, params: { identity: identity, clear: ek } });
			else if (op.type === 'add') ops.push({ label: op.key, params: { identity: identity, _set: { attribute: op.key, value: [op.value] } } });
		});
		if (!ops.length) return;
		applyBtn.disabled = true; applyBtn.textContent = 'Applying…';
		let done = 0; const fails = [];
		for (let i = 0; i < ops.length; i++) {
			try {
				const r = await api.op('set', 'domainobject', ops[i].params);
				assertWriteOk(r, "'" + ops[i].label + "' modify failed");
				done++;
			} catch (e) { fails.push(ops[i].label + ': ' + e.message); }
		}
		applied = true;
		resultEl = h('div', { class: 'form-result' + (fails.length ? ' err' : '') },
			fails.length
				? '[-] ' + done + '/' + ops.length + ' applied — ' + fails.join('  ·  ')
				: '[+] ' + done + ' operation' + (done === 1 ? '' : 's') + ' committed via Set-DomainObject');
		toast(fails.length ? 'error' : 'success',
			fails.length ? (done + '/' + ops.length + ' attribute changes applied')
				: (done + ' attribute change' + (done === 1 ? '' : 's') + ' applied'));
		rebuild();
	}
	rebuild();
}

/* every domain group's sAMAccountName, for the Add-to-Group picker —
   cached for the page lifetime so the dropdown is instant after first use. */
let _groupCache = null;
async function groupSuggestions() {
	if (_groupCache) return _groupCache;
	const out = [];
	try {
		const groups = await api.op('get', 'domaingroup', { properties: ['sAMAccountName'] });
		(groups || []).forEach(e => {
			const a = e.attributes || {};
			const sam = Array.isArray(a.sAMAccountName) ? a.sAMAccountName[0] : a.sAMAccountName;
			if (sam && out.indexOf(sam) < 0) out.push(sam);
		});
		out.sort((x, y) => x.toLowerCase().localeCompare(y.toLowerCase()));
		_groupCache = out;
	} catch (e) { /* leave uncached so the next modal open can retry */ }
	return out;
}

/* every domain user's sAMAccountName, for the group-member picker — cached. */
let _userCache = null;
async function userSuggestions() {
	if (_userCache) return _userCache;
	const out = [];
	try {
		const users = await api.op('get', 'domainuser', { properties: ['sAMAccountName'] });
		(users || []).forEach(e => {
			const a = e.attributes || {};
			const sam = Array.isArray(a.sAMAccountName) ? a.sAMAccountName[0] : a.sAMAccountName;
			if (sam && out.indexOf(sam) < 0) out.push(sam);
		});
		out.sort((x, y) => x.toLowerCase().localeCompare(y.toLowerCase()));
		_userCache = out;
	} catch (e) { /* leave uncached so the next modal open can retry */ }
	return out;
}

/* OU / container suggestions for the create dialogs — domain root + the
   well-known containers where default accounts live + every Get-DomainOU.
   Cached for the page lifetime so each modal open is instant. */
let _ouCache = null;
async function ouSuggestions() {
	if (_ouCache) return _ouCache;
	const opts = [];
	try {
		const info = await api.get('/api/get/domaininfo').catch(() => ({}));
		const root = info && info.root_dn;
		if (root) opts.push('CN=Users,' + root, 'CN=Computers,' + root);
		const ous = await api.op('get', 'domainou', { properties: ['distinguishedName'] });
		(ous || []).forEach(e => {
			const a = e.attributes || {};
			const dn = e.dn || (Array.isArray(a.distinguishedName) ? a.distinguishedName[0] : a.distinguishedName);
			if (dn && opts.indexOf(dn) < 0) opts.push(dn);
		});
		_ouCache = opts;
	} catch (e) { /* leave uncached so a later open can retry */ }
	return opts;
}
function fillDatalist(dl) {
	ouSuggestions().then(opts => opts.forEach(dn => dl.appendChild(h('option', { value: dn }))));
}

/* ---- create dialogs: + New User / + Add Computer ---- */
function newUserModal(onDone) {
	const sam  = h('input', { placeholder: 'sAMAccountName, e.g. j.smith', spellcheck: 'false', autocomplete: 'off',
		oninput: e => { e.target.value = e.target.value.replace(/\s/g, ''); } });
	const pwd  = h('input', { type: 'password' });
	const pwd2 = h('input', { type: 'password' });
	const bar  = h('div.pwd-strength', h('div.seg'), h('div.seg'), h('div.seg'), h('div.seg'));
	const lbl  = h('div.pwd-strength-label', 'enter password');
	const mism = h('div.form-help', { style: { color: 'var(--red)' } }, "passwords don't match");
	mism.hidden = true;
	const ouDl = h('datalist', { id: 'pv-newuser-ou' });
	const ou   = h('input', { placeholder: 'blank = default CN=Users container', spellcheck: 'false',
		autocomplete: 'off', list: 'pv-newuser-ou' });
	fillDatalist(ouDl);
	const result = h('div.form-result'); result.hidden = true;
	function recalc() {
		const p = pwd.value; let s = 0;
		if (p.length >= 8) s++;
		if (p.length >= 14) s++;
		if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
		if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++;
		bar.setAttribute('data-s', s);
		lbl.textContent = ['enter password', 'weak', 'fair', 'good', 'strong'][s];
		mism.hidden = !(pwd2.value && pwd.value !== pwd2.value);
	}
	pwd.oninput = recalc; pwd2.oninput = recalc;
	const body = h('div.form-stack',
		field('sAMAccountName', sam),
		field('Password', pwd, h('div', bar, lbl)),
		field('Confirm', pwd2, mism),
		field('OU / Path', ou, ouDl),
		h('div.form-help', { html: 'Creates an <span class="em">objectClass=user</span> entry — requires '
			+ '<span class="em">CreateChild</span> on the target container.' }),
		result);
	const m = modal({ cmd: 'Add-DomainUser', subject: '(new user)', width: 480, body: body });
	const submit = btn('Create user', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		recalc();
		const name = sam.value.trim();
		if (!name) { toast('error', 'enter a sAMAccountName'); return; }
		if (!pwd.value || pwd.value !== pwd2.value) { toast('error', 'enter and confirm a password'); return; }
		submit.disabled = true; submit.textContent = 'Creating…';
		try {
			const params = { username: name, password: pwd.value };
			if (ou.value.trim()) params.basedn = ou.value.trim();
			const r = await api.op('add', 'domainuser', params);
			assertWriteOk(r, "Failed to create user '" + name + "' (container not found or access denied)");
			sam.disabled = pwd.disabled = pwd2.disabled = ou.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] User '" + name + "' created";
			toast('success', "user '" + name + "' created");
			if (onDone) onDone();   /* refresh the table now — independent of how the modal is closed */
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Create user';
		}
	}
}

function addComputerModal(onDone) {
	const name = h('input', { placeholder: 'computer name, e.g. ATK01', spellcheck: 'false', autocomplete: 'off' });
	const sub  = h('div.form-help', { style: { color: 'var(--text-2)' } });
	name.oninput = () => {
		name.value = name.value.replace(/[^a-zA-Z0-9$-]/g, '');
		const n = name.value.replace(/\$$/, '');
		sub.textContent = n ? n + '$   (machine account)' : '';
	};
	const pwd = h('input', { type: 'text', placeholder: 'blank = auto-generate a 32-char password',
		spellcheck: 'false', autocomplete: 'off', style: { flex: 1 } });
	const gen = btn('⚄ Generate', null, () => {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const a = new Uint32Array(24);
		if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(a);
		let p = '';
		for (let i = 0; i < 24; i++) p += chars[(a[i] || Math.floor(Math.random() * 1e9)) % chars.length];
		pwd.value = p;
	});
	const ouDl = h('datalist', { id: 'pv-newcomp-ou' });
	const ou   = h('input', { placeholder: 'blank = default CN=Computers container', spellcheck: 'false',
		autocomplete: 'off', list: 'pv-newcomp-ou' });
	fillDatalist(ouDl);
	const result = h('div.form-result'); result.hidden = true;
	const body = h('div.form-stack',
		field('Computer name', name, sub),
		field('Password', h('div', { style: { display: 'flex', gap: '6px' } }, pwd, gen)),
		field('OU / Path', ou, ouDl),
		h('div.form-warn', { html: 'ℹ&nbsp; Uses <span class="em">MachineAccountQuota</span> — by default any '
			+ 'authenticated user may add up to 10 machine accounts. Common RBCD / shadow-credential primitive.' }),
		result);
	const m = modal({ cmd: 'Add-DomainComputer', subject: '(new computer)', width: 480, body: body });
	const submit = btn('Add computer', 'primary', doSubmit);
	m.setFooter([btn('Cancel', null, m.close), submit]);
	async function doSubmit() {
		const cn = name.value.trim();
		if (!cn) { toast('error', 'enter a computer name'); return; }
		submit.disabled = true; submit.textContent = 'Creating…';
		try {
			const params = { computer_name: cn };
			if (pwd.value.trim()) params.computer_pass = pwd.value.trim();
			if (ou.value.trim()) params.basedn = ou.value.trim();
			const r = await api.op('add', 'domaincomputer', params);
			assertWriteOk(r, "Failed to create computer '" + cn + "' (MachineAccountQuota reached or access denied)");
			name.disabled = pwd.disabled = gen.disabled = ou.disabled = true;
			result.className = 'form-result'; result.hidden = false;
			result.textContent = "[+] Computer '" + cn + (cn.endsWith('$') ? '' : '$') + "' created";
			toast('success', "computer '" + cn + "' created");
			if (onDone) onDone();   /* refresh the table now — independent of how the modal is closed */
			m.setFooter(btn('Done', 'primary', m.close));
		} catch (e) {
			result.className = 'form-result err'; result.hidden = false;
			result.textContent = '[-] ' + e.message;
			submit.disabled = false; submit.textContent = 'Add computer';
		}
	}
}

/* ---- CSV export of the current (client-filtered) result set ---- */
function csvCell(v) {
	let s = v == null ? '' : String(v);
	if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
	return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function downloadCsv(name, columns, rows) {
	const lines = [columns.map(c => csvCell(c.label)).join(',')];
	rows.forEach(r => lines.push(columns.map(c => csvCell(r[c.key])).join(',')));
	const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
	const url = URL.createObjectURL(blob);
	const a = h('a', { href: url, download: name });
	document.body.appendChild(a); a.click(); a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ============================ generic table page ============================ */
function tablePage(cfg) {
	const main = $('#main');
	let allRows = [], q = '', activeFilter = cfg.filters ? cfg.filters[0].k : 'all';

	const crumb = h('span.crumbs');
	const search = window.PV.searchField(v => { q = v; refresh(); }, cfg.searchPlaceholder);
	const tabsEl = h('div.tabs');
	const inspectorBody = h('div.props', h('div.empty', 'select a row'));
	const inspectorSub = h('span.muted.xs.mono');
	function showInspector(row) {
		inspectorSub.textContent = cfg.rowKey(row);
		clear(inspectorBody); cfg.inspector(row, inspectorBody);
		insp.show();
	}
	const g = grid(cfg.columns, {
		rowKey: cfg.rowKey, empty: 'no results — run a query', sort: cfg.sort,
		onRow: showInspector,
		onRowContext: cfg.contextMenu
			? (row, ev) => { showInspector(row); contextMenu(ev.clientX, ev.clientY, cfg.contextMenu(row)); }
			: null
	});
	const insp = inspectorPane('Inspector', inspectorSub, inspectorBody, () => g);

	main.append(
		h('div.page-head', h('span.title', cfg.title), crumb, h('span.grow'),
			h('div.toolbar', search,
				btn('⟲ Refresh', null, () => load()),
				cfg.action ? btn(cfg.action.label, 'primary', cfg.action.run) : null)),
		tabsEl,
		h('div.split', h('div.pane.fill', g.el), insp.el));

	function buildTabs() {
		clear(tabsEl);
		(cfg.filters || []).forEach(f => {
			const n = f.k === 'all' ? allRows.length : allRows.filter(f.test).length;
			tabsEl.appendChild(h('div', { class: 'tab' + (f.k === activeFilter ? ' active' : ''),
				onclick: () => { activeFilter = f.k; buildTabs(); refresh(); } }, f.label + ' (' + n + ')'));
		});
	}
	function refresh() {
		const filt = (cfg.filters || []).find(f => f.k === activeFilter);
		let rows = filt && filt.test ? allRows.filter(filt.test) : allRows;
		if (q) {
			const t = q.toLowerCase();
			rows = rows.filter(r => cfg.searchKeys.some(k => String(r[k] == null ? '' : r[k]).toLowerCase().includes(t)));
		}
		g.setData(rows);
		crumb.textContent = '/ ' + rows.length + ' / ' + allRows.length;
	}
	async function load() {
		const done = withSpinner(g.el);
		try {
			allRows = await cfg.fetch();
			done(); buildTabs(); refresh();
		} catch (e) { done(); toast('error', e.message); buildTabs(); refresh(); }
	}
	load();
}

/* ---- inspector primitives ---- */
function inspectorHead(name, sub, tags) {
	return h('div.inspector-head', h('div.nm', name), h('div.sub', sub), h('div.tags', tags));
}
function actionsGroup(actions) {
	return propGroup('Actions', h('div.actions-grid', actions.map(a =>
		h('button', { class: 'btn' + (a.primary ? ' primary' : a.danger ? ' danger' : ''),
			onclick: a.run }, a.label))));
}

/* ============================ QUERY-FORM TABLE PAGE ============================
   Users/Computers: top input boxes (Identity/SearchBase/LDAPFilter/Properties) +
   filter-flag chips. Nothing is queried until "Run Query" is pressed — the page
   does NOT walk the directory on visit. */
const VAL_KEYS = ['Identity', 'SearchBase', 'LDAPFilter', 'Properties'];
/* mutually exclusive flag pairs (by parser dest) */
const EXCL = [['enabled', 'disabled'], ['allowdelegation', 'disallowdelegation'],
	['workstation', 'notworkstation']];
/* flag display name -> Get-DomainUser parser dest */
const USER_FLAGS = [
	{ name: 'AdminCount', key: 'admincount', severity: 'danger', hint: 'adminCount=1 — AdminSDHolder protected' },
	{ name: 'Enabled', key: 'enabled' },
	{ name: 'Disabled', key: 'disabled', severity: 'warn' },
	{ name: 'LockedOut', key: 'lockedout', severity: 'warn' },
	{ name: 'PassExpired', key: 'password_expired', severity: 'warn' },
	{ name: 'PassNotRequired', key: 'passnotrequired', severity: 'danger', hint: 'UAC PASSWD_NOTREQD' },
	{ name: 'SPN', key: 'spn', severity: 'warn', hint: 'servicePrincipalName set — kerberoastable' },
	{ name: 'PreauthNotRequired', key: 'preauthnotrequired', severity: 'danger', hint: 'DONT_REQ_PREAUTH — AS-REP roastable' },
	{ name: 'AllowDelegation', key: 'allowdelegation' },
	{ name: 'DisallowDelegation', key: 'disallowdelegation' },
	{ name: 'Unconstrained', key: 'unconstrained', severity: 'danger', hint: 'TRUSTED_FOR_DELEGATION' },
	{ name: 'TrustedToAuth', key: 'trustedtoauth', severity: 'warn', hint: 'S4U2Self' },
	{ name: 'RBCD', key: 'rbcd', severity: 'warn' },
	{ name: 'ShadowCred', key: 'shadowcred', severity: 'warn' }
];
/* flag display name -> Get-DomainComputer parser dest */
const COMP_FLAGS = [
	{ name: 'Enabled', key: 'enabled' },
	{ name: 'Disabled', key: 'disabled', severity: 'warn' },
	{ name: 'Workstation', key: 'workstation' },
	{ name: 'NotWorkstation', key: 'notworkstation' },
	{ name: 'ExcludeDCs', key: 'excludedcs' },
	{ name: 'Printers', key: 'printers' },
	{ name: 'SPN', key: 'spn' },
	{ name: 'LAPS', key: 'laps', severity: 'warn' },
	{ name: 'Obsolete', key: 'obsolete', severity: 'danger', hint: 'EOL OS' },
	{ name: 'BitLocker', key: 'bitlocker' },
	{ name: 'GMSAPassword', key: 'gmsapassword', severity: 'warn' },
	{ name: 'Unconstrained', key: 'unconstrained', severity: 'danger', hint: 'TRUSTED_FOR_DELEGATION' },
	{ name: 'TrustedToAuth', key: 'trustedtoauth', severity: 'warn' },
	{ name: 'RBCD', key: 'rbcd', severity: 'warn' },
	{ name: 'ShadowCred', key: 'shadowcred', severity: 'warn' },
	{ name: 'ResolveSIDs', key: 'resolvesids' }
];

function queryTablePage(cfg) {
	const main = $('#main');
	const flagState = {};
	const vals = { Identity: '', SearchBase: '', LDAPFilter: '', Properties: '' };
	let results = null, lastRun = null, running = false, q = '', showFlags = false;
	let activeColumns = null;   /* columns of the last query — used by Export CSV */

	const crumb = h('span.crumbs');
	const search = window.PV.searchField(v => { q = v; renderTable(); }, 'filter results (client-side)…');
	const flagBtn = h('button.flagbtn');
	const csvBtn = h('button.btn', { disabled: true, onclick: () => exportCsv() }, 'Export CSV');
	const createBtn = cfg.createModal
		? h('button.btn', { onclick: () => cfg.createModal(runQuery) }, cfg.createLabel || '+ New')
		: null;
	const runBtn = h('button.btn.primary', { onclick: () => runQuery() }, '▷ Run Query');
	const head = h('div.page-head', h('span.title', cfg.title), crumb, h('span.grow'),
		h('div.toolbar', search, flagBtn, createBtn, csvBtn, runBtn));

	/* --- filter panel --- */
	const inputs = {};
	let sbLoaded = false;
	/* lazily fill SearchBase suggestions: Get-DomainOU gives the OUs, but
	   search bases also include the domain root and well-known containers
	   (CN=Users, CN=Computers, …) where default accounts actually live */
	async function loadSearchBases(listEl) {
		if (sbLoaded) return;
		sbLoaded = true;
		try {
			const info = await api.get('/api/get/domaininfo').catch(() => ({}));
			const root = info && info.root_dn;
			const opts = [];
			if (root) {
				opts.push(root);
				['CN=Users', 'CN=Computers', 'CN=Builtin', 'CN=Managed Service Accounts',
				 'CN=System', 'OU=Domain Controllers'].forEach(c => opts.push(c + ',' + root));
			}
			const ous = await api.op('get', 'domainou', { properties: ['distinguishedName'] });
			(ous || []).forEach(e => {
				const a = e.attributes || {};
				const dn = e.dn || (Array.isArray(a.distinguishedName) ? a.distinguishedName[0] : a.distinguishedName);
				if (dn && opts.indexOf(dn) < 0) opts.push(dn);
			});
			clear(listEl);
			opts.forEach(dn => listEl.appendChild(h('option', { value: dn })));
		} catch (e) { sbLoaded = false; }   /* allow a retry on next focus */
	}
	function flagInput(key, ph, suggest) {
		const inp = h('input', { spellcheck: 'false', autocomplete: 'off', placeholder: ph,
			oninput: e => { vals[key] = e.target.value; renderFlagBtn(); },
			onkeydown: e => { if (e.key === 'Enter') runQuery(); } });
		inputs[key] = inp;
		const span = h('span.flag-input', h('span.pfx', '-' + key), inp);
		if (suggest) {
			const dl = h('datalist', { id: 'pv-searchbase-list' });
			inp.setAttribute('list', 'pv-searchbase-list');
			inp.addEventListener('focus', () => loadSearchBases(dl));
			span.appendChild(dl);
		}
		return span;
	}
	const filterInputs = h('div.filter-inputs',
		flagInput('Identity', 'sAMAccountName, SID, or wildcard'),
		flagInput('SearchBase', 'OU / container DN  —  type or pick a suggestion', true),
		flagInput('LDAPFilter', '(&(objectClass=...)...)'),
		flagInput('Properties', 'comma-separated, or *  —  blank = default set'));
	const flagGroups = h('div.flag-groups');
	cfg.flags.forEach(f => {
		f._chip = h('span', { class: 'flag-chip' + (f.severity ? ' ' + f.severity : ''),
			title: f.hint || f.name, onclick: () => toggleFlag(f) }, f.name);
		flagGroups.appendChild(f._chip);
	});
	const filterPanel = h('div.filter-panel', filterInputs, flagGroups,
		h('div', { style: { display: 'flex', gap: '6px', justifyContent: 'flex-end' } },
			h('button.btn', { onclick: () => clearAll() }, '⟲ Clear')));

	const resultBar = h('div');
	const fillPane = h('div.pane.fill', { style: { display: 'flex', flexDirection: 'column', minHeight: 0 } });
	const inspectorBody = h('div.props', h('div.empty', 'select a row'));
	const inspectorSub = h('span.muted.xs.mono');
	const insp = inspectorPane('Inspector', inspectorSub, inspectorBody, () => g);
	main.append(head, filterPanel, resultBar, h('div.split', fillPane, insp.el));

	/* hooks handed to context menus / inspector actions so a write that
	   changes the row set (delete) can update the table without a re-query */
	const pageCtx = {
		removeRow: function (row) {
			if (results) { results = results.filter(function (r) { return r !== row; }); renderTable(); }
			insp.hide();   /* the inspected row is gone */
		},
		refresh: function () { runQuery(); }
	};
	function showInspector(row) {
		inspectorSub.textContent = cfg.rowKey(row);
		clear(inspectorBody); cfg.inspector(row, inspectorBody, pageCtx);
		insp.show();
	}
	/* the grid is rebuilt per query so its columns track the API response */
	let g = null;
	function makeGrid(columns) {
		return grid(columns, { rowKey: cfg.rowKey, sort: cfg.sort, empty: 'no matching rows',
			onRow: showInspector,
			onRowContext: cfg.contextMenu
				? (row, ev) => { showInspector(row); contextMenu(ev.clientX, ev.clientY, cfg.contextMenu(row, pageCtx)); }
				: null });
	}
	/* flatten an entry's attributes onto the row so every property — default
	   or user-appended — is addressable by a dynamic column. The DC normalises
	   attribute names to their schema casing (e.g. dnsHostName -> dNSHostName),
	   so every key is also aliased lowercase to make column lookup casing-proof */
	function flatAttrs(entry) {
		const a = entry.attributes || {}, o = {};
		for (const k in a) {
			const v = Array.isArray(a[k]) ? a[k].join(', ') : a[k];
			o[k] = v;
			const lk = k.toLowerCase();
			if (lk !== k && !(lk in a)) o[lk] = v;
		}
		return o;
	}

	function toggleFlag(f) {
		if (flagState[f.key]) delete flagState[f.key];
		else {
			flagState[f.key] = true;
			EXCL.forEach(pair => { if (pair.indexOf(f.key) > -1)
				pair.forEach(k => { if (k !== f.key) delete flagState[k]; }); });
		}
		cfg.flags.forEach(x => x._chip.classList.toggle('on', !!flagState[x.key]));
		renderFlagBtn();
	}
	function clearAll() {
		Object.keys(flagState).forEach(k => delete flagState[k]);
		VAL_KEYS.forEach(k => { vals[k] = ''; inputs[k].value = ''; });
		cfg.flags.forEach(x => x._chip.classList.remove('on'));
		renderFlagBtn();
	}
	function activeCount() {
		return Object.keys(flagState).filter(k => flagState[k]).length
			+ VAL_KEYS.filter(k => vals[k].trim()).length;
	}
	function cmdParts() {
		const parts = [];
		cfg.flags.forEach(f => { if (flagState[f.key]) parts.push({ flag: f.name }); });
		VAL_KEYS.forEach(k => { if (vals[k].trim()) parts.push({ flag: k, val: vals[k].trim() }); });
		return parts;
	}
	function renderCmd(host, parts) {
		host.appendChild(h('span.cmdlet', cfg.cmdlet));
		parts.forEach(p => {
			host.append(' ', h('span.flag', '-' + p.flag));
			if (p.val != null) host.append(' ', h('span.str', "'" + p.val + "'"));
		});
		if (!parts.length) host.appendChild(h('span.muted', '  (no filters — returns all objects)'));
	}
	function renderFlagBtn() {
		clear(flagBtn);
		flagBtn.className = 'flagbtn' + (showFlags ? ' on' : '');
		flagBtn.append((showFlags ? '▾' : '▸') + ' Flags');
		const n = activeCount();
		if (n) flagBtn.appendChild(h('span.cnt', String(n)));
	}
	flagBtn.onclick = () => { showFlags = !showFlags; filterPanel.hidden = !showFlags; renderFlagBtn(); };
	function renderResultBar() {
		clear(resultBar);
		resultBar.className = lastRun ? 'result-bar' : '';
		if (!lastRun) return;
		const cmd = h('span.cmd', h('span.prompt', 'PV ›'));
		renderCmd(cmd, lastRun.parts);
		resultBar.append(cmd, h('span.meta', lastRun.error
			? [h('span.err', '✕'), ' ' + lastRun.error]
			: [h('span.ok', '✓'), ' ', h('span.num', String(lastRun.count)), ' rows · ',
			   h('span.num', String(lastRun.ms)), 'ms · queried ' + lastRun.ts]));
	}
	function userProps() {
		return vals.Properties.split(',').map(s => s.trim()).filter(Boolean);
	}
	/* request set = curated default properties + user-appended -Properties (deduped) */
	function requestProps() {
		const seen = {}, out = [];
		cfg.reqProps.concat(userProps()).forEach(p => {
			const lk = p.toLowerCase();
			if (lk && lk !== '*' && !seen[lk]) { seen[lk] = 1; out.push(p); }
		});
		return out;
	}
	/* columns = curated default columns + one dynamic column per user-appended property */
	function buildColumns() {
		const cols = cfg.defaultColumns.slice();
		const seen = {};
		cfg.shownProps.forEach(p => seen[p.toLowerCase()] = 1);
		cfg.defaultColumns.forEach(c => seen[c.key.toLowerCase()] = 1);
		userProps().forEach(p => {
			const lk = p.toLowerCase();
			if (!lk || lk === '*' || seen[lk]) return;
			seen[lk] = 1;
			/* key by lowercase — flatAttrs aliases every attribute lowercase,
			   so the column resolves regardless of the casing the user typed */
			cols.push({ key: lk, label: p, render: v => fmtVal(v) });
		});
		return cols;
	}
	function buildArgs() {
		const args = { properties: requestProps() };
		if (cfg.fixedArgs) Object.assign(args, cfg.fixedArgs);   /* always-on flags, e.g. include_ip */
		if (vals.Identity.trim()) args.identity = vals.Identity.trim();
		if (vals.SearchBase.trim()) args.searchbase = vals.SearchBase.trim();
		if (vals.LDAPFilter.trim()) args.ldapfilter = vals.LDAPFilter.trim();
		Object.keys(flagState).forEach(k => { if (flagState[k]) args[k] = true; });
		return args;
	}
	function renderTable() {
		clear(fillPane);
		csvBtn.disabled = (results === null);
		if (running) {
			fillPane.appendChild(h('div.empty-pane',
				h('div.glyph', h('div.spinner.lg')),
				h('div.title-line', 'Querying domain…'),
				h('div', 'running ' + cfg.cmdlet + ' against the DC')));
			return;
		}
		if (results === null) {
			fillPane.appendChild(h('div.empty-pane',
				h('div.glyph', '⌕'),
				h('div.title-line', 'No query has been run.'),
				h('div', 'Fill the inputs / flags above, then press ',
					h('span', { style: { color: 'var(--accent)' } }, '▷ Run Query'), '.'),
				h('div.hint', 'Nothing is loaded by default — this avoids walking the entire directory on page open.'),
				h('button.btn.primary.run-btn', { onclick: () => runQuery() }, '▷ Run Query')));
			return;
		}
		const view = currentView();
		fillPane.appendChild(g.el);
		g.setData(view);
		crumb.textContent = '/ ' + view.length + (q ? ' of ' + results.length : '') + ' shown';
		/* no auto-select — the Inspector stays closed until a row is clicked */
	}
	/* rows currently in the table = query results narrowed by the search box */
	function currentView() {
		if (results === null) return [];
		if (!q) return results;
		const t = q.toLowerCase();
		return results.filter(r => cfg.searchKeys.some(k =>
			String(r[k] == null ? '' : r[k]).toLowerCase().indexOf(t) > -1));
	}
	function exportCsv() {
		if (results === null) { toast('error', 'run a query first'); return; }
		const view = currentView();
		if (!view.length) { toast('error', 'no rows to export'); return; }
		const cols = activeColumns || buildColumns();
		const fname = cfg.method + '-' + new Date().toISOString().slice(0, 19).replace(/[:T-]/g, '') + '.csv';
		downloadCsv(fname, cols, view);
		toast('success', 'exported ' + view.length + ' row' + (view.length === 1 ? '' : 's') + ' to ' + fname);
	}
	async function runQuery() {
		if (running) return;
		running = true; runBtn.disabled = true; runBtn.textContent = 'Running…';
		insp.hide();   /* drop any stale selection from the previous run */
		activeColumns = buildColumns();   /* snapshot columns for this run (table + CSV) */
		g = makeGrid(activeColumns);
		renderTable();
		const parts = cmdParts();
		const t0 = performance.now();
		try {
			/* raw:true — timestamps come back as parseable GMT strings (not
			   pre-formatted "DD/MM/YYYY (N days ago)"), so columns can compute
			   age; SIDs stay readable and uacFlags() handles the raw int. */
			const data = await api.op('get', cfg.method, { args: buildArgs(), raw: true });
			/* mapRow first, raw flattened attributes last: a user-appended
			   -Properties column keys into the raw LDAP attribute, so flatAttrs
			   must win any name collision (e.g. `name`) over mapRow's synthetic
			   keys. mapRow's computed keys (enabled/role/uac/…) aren't LDAP
			   attribute names, so they survive unclobbered. */
			results = (Array.isArray(data) ? data : []).map(e => Object.assign({}, cfg.mapRow(e), flatAttrs(e)));
			lastRun = { parts: parts, count: results.length,
				ms: Math.round(performance.now() - t0), ts: new Date().toTimeString().slice(0, 8), error: null };
		} catch (e) {
			results = []; toast('error', e.message);
			lastRun = { parts: parts, count: 0,
				ms: Math.round(performance.now() - t0), ts: new Date().toTimeString().slice(0, 8), error: e.message };
		}
		running = false; runBtn.disabled = false; runBtn.textContent = '▷ Run Query';
		renderResultBar(); renderTable();
	}

	filterPanel.hidden = !showFlags;   /* filter panel collapsed by default */
	renderFlagBtn();
	runQuery();   /* auto-query on page visit with the default (no-filter) args */
}

/* ============================ USERS ============================ */
function userMenu(u, ctx) {
	return [
		{ header: u.sam, iconType: 'user', tag: u.admin ? 'admin' : 'user' },
		{ divider: true },
		{ section: 'ENUMERATE' },
		{ icon: '≡', label: 'Get-Object',    onClick: () => act.getObject(u) },
		{ icon: '⚿', label: 'Get-Acl',       onClick: () => act.getAcl(u) },
		{ icon: '▥', label: 'Find Sessions', onClick: () => runCmd('Find-DomainUserLocation -UserIdentity ' + u.sam) },
		{ icon: '◌', label: 'Find in Graph', onClick: () => { location.href = '/graph'; } },
		{ divider: true },
		{ section: 'WRITE' },
		{ icon: '⚙', label: 'Edit…',            onClick: () => editAttributesModal(u) },
		{ icon: '✎', label: 'Change Password…', onClick: () => setPasswordModal(u) },
		{ icon: '+', label: 'Add to Group…',    onClick: () => addToGroupModal(u) },
		{ icon: '♔', label: 'Set Owner…',       onClick: () => setOwnerModal(u, 'user') },
		{ divider: true },
		{ icon: '✕', label: 'Delete user…', danger: true,
			onClick: () => deleteObjectModal(u, 'user', () => ctx && ctx.removeRow(u)) }
	];
}

window.PV.pages.users = function () {
	queryTablePage({
		title: 'Users', method: 'domainuser', cmdlet: 'Get-DomainUser', flags: USER_FLAGS,
		searchKeys: ['sam', 'name', 'title'], rowKey: r => r.sam, sort: 'sAMAccountName',
		contextMenu: userMenu, createModal: newUserModal, createLabel: '+ New User',
		reqProps: ['sAMAccountName','name','displayName','title','userAccountControl','adminCount',
			'servicePrincipalName','msDS-AllowedToDelegateTo','pwdLastSet','lastLogonTimestamp',
			'distinguishedName','memberOf','objectSid','description'],
		shownProps: ['sAMAccountName','displayName','title','adminCount','pwdLastSet','lastLogonTimestamp',
			'userAccountControl','distinguishedName'],
		mapRow: e => {
			const a = e.attributes || {};
			const fl = uacFlags(a.userAccountControl);
			const deleg = fl.includes('TRUSTED_FOR_DELEGATION') ? 'Unconstrained'
				: a['msDS-AllowedToDelegateTo'] ? 'Constrained'
				: fl.includes('TRUSTED_TO_AUTH_FOR_DELEGATION') ? 'Constrained' : '-';
			return {
				sam: attr(a, 'sAMAccountName') || '', name: attr(a, 'displayName') || attr(a, 'name') || '',
				title: attr(a, 'title') || '', enabled: !fl.includes('ACCOUNTDISABLE'),
				admin: String(attr(a, 'adminCount')) === '1', spn: !!a.servicePrincipalName,
				asrep: fl.includes('DONT_REQ_PREAUTH'), deleg: deleg,
				pwdAge: ageDays(attr(a, 'pwdLastSet')),
				lastLogon: attr(a, 'lastLogonTimestamp') || '',
				_ou: ouOf(e.dn || attr(a, 'distinguishedName')),
				dn: e.dn || attr(a, 'distinguishedName'), sid: attr(a, 'objectSid') || '',
				desc: attr(a, 'description') || '', groups: a.memberOf ? (Array.isArray(a.memberOf) ? a.memberOf : [a.memberOf]) : [],
				uac: fl
			};
		},
		defaultColumns: [
			{ key: 'sAMAccountName', label: 'sAMAccountName', w: 150, color: () => 'var(--accent)' },
			{ key: 'displayName', label: 'Display Name', w: 175 },
			{ key: 'title', label: 'title', w: 140, color: () => 'var(--text-2)' },
			{ key: 'enabled', label: 'State', w: 80, render: v => v ? tag('enabled', 'green') : tag('disabled', 'gray') },
			{ key: 'adminCount', label: 'adminCount', w: 95,
				render: v => String(v) === '1' ? tag('1', 'red') : h('span.muted', '—') },
			{ key: 'pwdLastSet', label: 'pwdLastSet', w: 115, render: v => daysCell(v), sortVal: dateSort },
			{ key: 'lastLogonTimestamp', label: 'Last Logon', w: 150, render: v => daysCell(v), sortVal: dateSort },
			{ key: '_ou', label: 'OU', color: () => 'var(--text-2)' }
		],
		inspector: (u, body, ctx) => {
			/* memberOf panel — rebuilt in place when Add-to-Group succeeds */
			function buildMemberOf(groups) {
				return propGroup('memberOf (' + groups.length + ')',
					h('div', { style: { padding: '4px 10px' } }, groups.length
						? groups.map(g => h('div.mono.sm', { style: { padding: '2px 0', color: 'var(--text-2)' } },
							'↳ ' + (g.match(/CN=([^,]+)/i) || [, g])[1]))
						: h('span.muted', '—')));
			}
			let moEl = buildMemberOf(u.groups);
			body.append(
				inspectorHead(u.name || u.sam, u.sam + '   ·   right-click row for actions', [
					u.enabled ? tag('enabled', 'green') : tag('disabled', 'gray'),
					u.admin && tag('admin', 'red'), u.spn && tag('SPN', 'yellow'),
					u.asrep && tag('AS-REP', 'red'), u.deleg !== '-' && tag(u.deleg.toLowerCase(), 'yellow')
				].filter(Boolean)),
				actionsGroup([
					{ label: 'Get-Object', run: () => act.getObject(u) },
					{ label: 'Get-Acl', run: () => act.getAcl(u) },
					{ label: 'Edit', run: () => editAttributesModal(u) },
					{ label: 'Set-Password', run: () => setPasswordModal(u) },
					{ label: 'Add to Group', run: () => addToGroupModal(u, added => {
						u.groups.push(added);
						const fresh = buildMemberOf(u.groups);
						moEl.replaceWith(fresh); moEl = fresh;
					}) },
					{ label: 'Set-Owner', run: () => setOwnerModal(u, 'user') },
					{ label: 'Delete', danger: true,
						run: () => deleteObjectModal(u, 'user', () => ctx && ctx.removeRow(u)) }
				]),
				moEl,
				propGroup('Raw LDAP',
					h('div', { style: { padding: '6px 10px', fontFamily: 'var(--font-mono)',
						fontSize: 'var(--fs-xs)', color: 'var(--text-2)', lineHeight: 1.6 } },
						h('div', h('span.muted', 'dn: '), u.dn || '—'),
						h('div', h('span.muted', 'objectSid: '), u.sid || '—'),
						h('div', h('span.muted', 'accountFlags: '), u.uac.join(' | ') || '—'),
						h('div', h('span.muted', 'description: '), u.desc || '—'))));
		}
	});
};

/* ============================ COMPUTERS ============================ */
function computerMenu(c, ctx) {
	return [
		{ header: c.name, iconType: 'computer', tag: c.role },
		{ divider: true },
		{ section: 'ENUMERATE' },
		{ icon: '◆', label: 'Test-AdminAccess', onClick: () => runCmd('Test-AdminAccess -Computer ' + c.name) },
		{ icon: '▥', label: 'Get-Sessions',     onClick: () => act.getSessions(c) },
		{ icon: '☺', label: 'Get-LoggedOn',     onClick: () => act.getLoggedOn(c) },
		{ icon: '▦', label: 'Get-Shares',       onClick: () => act.getShares(c) },
		{ icon: '⚿', label: 'Read LAPS',        onClick: () => act.readLaps(c) },
		{ icon: '◌', label: 'Find in Graph',    onClick: () => { location.href = '/graph'; } },
		{ divider: true },
		{ section: 'CONNECT' },
		{ icon: '▦', label: 'Connect SMB', shortcut: '→ smb', onClick: () => { location.href = '/smb'; } },
		{ divider: true },
		{ section: 'WRITE' },
		{ icon: '⚙', label: 'Edit…',      onClick: () => editAttributesModal(c) },
		{ icon: '♔', label: 'Set Owner…', onClick: () => setOwnerModal(c, 'computer') },
		{ divider: true },
		{ icon: '✕', label: 'Delete computer…', danger: true,
			onClick: () => deleteObjectModal(c, 'computer', () => ctx && ctx.removeRow(c)) }
	];
}

window.PV.pages.computers = function () {
	queryTablePage({
		title: 'Computers', method: 'domaincomputer', cmdlet: 'Get-DomainComputer', flags: COMP_FLAGS,
		searchKeys: ['name', 'os', 'dns'], rowKey: r => r.name, sort: 'sAMAccountName',
		contextMenu: computerMenu, createModal: addComputerModal, createLabel: '+ Add Computer',
		fixedArgs: { include_ip: true },   /* -IncludeIP: resolve each host's A record → IPAddress */
		reqProps: ['sAMAccountName','name','dnsHostName','operatingSystem','operatingSystemVersion',
			'userAccountControl','servicePrincipalName','lastLogonTimestamp','distinguishedName'],
		shownProps: ['sAMAccountName','operatingSystem','lastLogonTimestamp','dnsHostName',
			'IPAddress','userAccountControl','distinguishedName','name'],
		mapRow: e => {
			const a = e.attributes || {};
			const fl = uacFlags(a.userAccountControl);
			const os = attr(a, 'operatingSystem') || '';
			const role = fl.includes('SERVER_TRUST_ACCOUNT') ? 'DC' : /server/i.test(os) ? 'SRV' : 'WS';
			const spn = a.servicePrincipalName ? (Array.isArray(a.servicePrincipalName) ? a.servicePrincipalName.length : 1) : 0;
			return {
				name: attr(a, 'name') || '', dns: attr(a, 'dNSHostName') || attr(a, 'dnsHostName') || '',
				role: role, os: os || '—', osVer: attr(a, 'operatingSystemVersion') || '',
				spnCount: spn,
				lastLogon: attr(a, 'lastLogonTimestamp') || '',
				_ou: ouOf(e.dn || attr(a, 'distinguishedName')),
				dn: e.dn || attr(a, 'distinguishedName'), uac: fl
			};
		},
		defaultColumns: [
			{ key: 'sAMAccountName', label: 'sAMAccountName', w: 150, color: () => 'var(--accent)' },
			{ key: 'role', label: 'Role', w: 64, render: v => tag(v, v === 'DC' ? 'red' : v === 'SRV' ? 'blue' : 'gray') },
			{ key: 'operatingSystem', label: 'operatingSystem', w: 185 },
			{ key: 'lastLogonTimestamp', label: 'Last Logon', w: 150, render: v => daysCell(v), sortVal: dateSort },
			{ key: '_ou', label: 'OU', w: 170, color: () => 'var(--text-2)' },
			{ key: 'dNSHostName', label: 'dnsHostName', w: 200, color: () => 'var(--accent)' },
			{ key: 'IPAddress', label: 'IP', w: 130, color: () => 'var(--text-2)' }
		],
		inspector: (c, body, ctx) => {
			body.append(
				inspectorHead(c.name, (c.dns || c.name) + '   ·   right-click row for actions', [
					tag(c.role, c.role === 'DC' ? 'red' : c.role === 'SRV' ? 'blue' : 'gray'),
					c.os !== '—' && tag(c.os, 'gray')
				].filter(Boolean)),
				actionsGroup([
					{ label: 'Test-AdminAccess', run: () => runCmd('Test-AdminAccess -Computer ' + c.name) },
					{ label: 'Get-Sessions', run: () => act.getSessions(c) },
					{ label: 'Get-LoggedOn', run: () => act.getLoggedOn(c) },
					{ label: 'Read LAPS', run: () => act.readLaps(c) },
					{ label: 'Edit', run: () => editAttributesModal(c) },
					{ label: 'Connect SMB', run: () => { location.href = '/smb'; } },
					{ label: 'Set-Owner', run: () => setOwnerModal(c, 'computer') },
					{ label: 'Delete', danger: true,
						run: () => deleteObjectModal(c, 'computer', () => ctx && ctx.removeRow(c)) }
				]),
				propGroup('Properties',
					h('div', { style: { padding: '4px 0' } },
						propRow('dns', c.dns || '—'),
						propRow('os', c.os + (c.osVer ? ' (' + c.osVer + ')' : '')),
						propRow('spn count', String(c.spnCount)),
						propRow('last logon', c.lastLogon || '—'),
						propRow('uac', c.uac.join(' | ') || '—'),
						propRow('dn', c.dn || '—'))));
		}
	});
};

/* ============================ GROUPS ============================ */
function groupScope(gt) {
	gt = parseInt(gt, 10); if (isNaN(gt)) return ['—', '—'];
	const sec = (gt & 0x80000000) ? 'Security' : 'Distribution';
	const scope = (gt & 2) ? 'Global' : (gt & 4) ? 'DomainLocal' : (gt & 8) ? 'Universal' : 'BuiltinLocal';
	return [scope, sec];
}
function groupMenu(g) {
	return [
		{ header: g.name, iconType: 'group', tag: g.builtin ? 'built-in' : g.scope },
		{ divider: true },
		{ section: 'ENUMERATE' },
		{ icon: '≡', label: 'Get-Object',   onClick: () => act.getObject(g) },
		{ icon: '⚿', label: 'Get-Acl',      onClick: () => act.getAcl(g) },
		{ icon: '◌', label: 'Find in Graph', onClick: () => { location.href = '/graph'; } },
		{ divider: true },
		{ section: 'WRITE' },
		{ icon: '⚙', label: 'Edit…',        onClick: () => editAttributesModal(g) },
		{ icon: '+', label: 'Add Member…',  onClick: () => addGroupMemberModal(g) }
	];
}
window.PV.pages.groups = function () {
	tablePage({
		title: 'Groups', searchPlaceholder: 'name or description…',
		searchKeys: ['name', 'desc'], rowKey: r => r.name, sort: 'name',
		contextMenu: groupMenu,
		fetch: async () => {
			const data = await api.get('/api/get/domaingroup');
			return (data || []).map(e => {
				const a = e.attributes || {};
				const [scope, type] = groupScope(attr(a, 'groupType'));
				const mem = a.member ? (Array.isArray(a.member) ? a.member.length : 1) : 0;
				const dn = e.dn || attr(a, 'distinguishedName') || '';
				return {
					name: attr(a, 'sAMAccountName') || attr(a, 'cn') || attr(a, 'name') || '',
					scope: scope, type: type, members: mem,
					builtin: /CN=Builtin/i.test(dn) || String(attr(a, 'adminCount')) === '1',
					gid: attr(a, 'objectSid') || '', desc: attr(a, 'description') || '', dn: dn
				};
			});
		},
		filters: [
			{ k: 'all', label: 'All', test: null },
			{ k: 'priv', label: 'Privileged', test: r => r.builtin },
			{ k: 'big', label: 'Populated', test: r => r.members > 0 }
		],
		columns: [
			{ key: 'name', label: 'Name', w: 220, color: (v, r) => r.builtin ? 'var(--red)' : 'var(--accent)' },
			{ key: 'scope', label: 'Scope', w: 120 },
			{ key: 'type', label: 'Type', w: 100, color: () => 'var(--text-2)' },
			{ key: 'members', label: 'Members', w: 90, color: v => v > 20 ? 'var(--yellow)' : 'var(--text-2)' },
			{ key: 'builtin', label: 'Built-in', w: 90, render: v => v ? tag('YES', 'red') : h('span.muted', '—') },
			{ key: 'gid', label: 'SID', w: 230, color: () => 'var(--muted)' },
			{ key: 'desc', label: 'Description', color: () => 'var(--text-2)' }
		],
		inspector: (g, body) => {
			body.append(
				inspectorHead(g.name, g.desc || g.gid, [
					g.builtin && tag('built-in', 'red'), tag(g.scope, 'gray'), tag(g.type, 'gray')
				].filter(Boolean)),
				actionsGroup([
					{ label: 'Add Member', run: () => addGroupMemberModal(g, loadMembers) },
					{ label: 'Get-Acl', run: () => act.getAcl(g) },
					{ label: 'Edit', run: () => editAttributesModal(g) }
				]));
			const memHost = h('div', { style: { padding: '4px 0' } }, h('div.empty', h('div.spinner')));
			body.appendChild(propGroup('Members', memHost));
			function loadMembers() {
				clear(memHost); memHost.appendChild(h('div.empty', h('div.spinner')));
				api.op('get', 'domaingroupmember', { identity: g.name }).then(mem => {
					clear(memHost);
					const list = mem || [];
					if (!list.length) { memHost.appendChild(h('div.muted.mono.sm',
						{ style: { padding: '6px 10px' } }, '— no members resolved')); return; }
					list.forEach(m => {
						const a = m.attributes || {};
						const mn = attr(a, 'MemberName') || '?';
						const mdn = attr(a, 'MemberDistinguishedName') || '';
						const msid = attr(a, 'MemberSID') || '';
						/* display and removal both resolve DN → SID → name */
						memHost.appendChild(h('div.row', { style: { gridTemplateColumns: '120px 1fr auto' } },
							h('span.k.mono', mn),
							h('span.v', mdn || msid || ''),
							h('button.attr-action.danger', { title: 'remove ' + mn + ' from group',
								onclick: () => removeGroupMemberModal(g, mn, mdn || msid || mn, loadMembers) }, '✕')));
					});
				}).catch(e => { clear(memHost); memHost.appendChild(h('div.muted.mono.sm',
					{ style: { padding: '6px 10px' } }, e.message)); });
			}
			loadMembers();
		}
	});
};
})();
