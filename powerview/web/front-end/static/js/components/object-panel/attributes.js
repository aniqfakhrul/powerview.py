import { moveObject } from './move-object.js';
import { beginLoading } from '../loading.js';
import { dnLabel, isDN, sameDN } from '../../core/dn.js';
import { attribute, recordName, values, textValue, objectType } from '../../core/directory.js';
import { accountDisabled, readableTime } from '../../core/ldap-values.js';
import { createRequestLane } from '../../core/request-lane.js';
import { notify } from '../notify.js';
import { typeIcon } from '../type-icon.js';
import { createValueEditor } from './value-editor.js';
import { button, dnText, element, setBusy } from '../../core/dom.js';

const VALUE_PREVIEW = 12;
const PROTECTED = /^(distinguishedname|name|cn|ou|objectclass|objectcategory|objectguid|objectsid|whencreated|whenchanged|usncreated|usnchanged|instancetype|ntsecuritydescriptor|unicodepwd|.*certificate.*|.*;binary|.*photo.*|.*jpeg.*|.*securitydescriptor.*|logonhours|repl.*|.*keycredential.*)$/i;

export const editableField = (name, value) => !PROTECTED.test(name) && !name.includes(';range=')
  && values(value).every((item) => ['string', 'boolean'].includes(typeof item) || (typeof item === 'number' && Number.isSafeInteger(item)));


function summary(record) {
  const count = Object.keys(record.attributes).length;
  const parts = [`${count} ${count === 1 ? 'attribute' : 'attributes'}`];
  const control = attribute(record, 'userAccountControl');
  if (values(control).length) parts.push(accountDisabled(control) ? 'Disabled' : 'Enabled');
  return parts.join(' · ');
}

function timeValue(raw, time) {
  const node = element('span', 'value', time.text);
  node.title = raw;
  if (time.relative) node.append(element('span', 'value__note', time.relative));
  return node;
}

function editableText(value) {
  return values(value).map((item) => (typeof item === 'boolean' ? String(item).toUpperCase() : String(item)));
}

export function createAttributes({ root, directory, scope, status, guard, onNavigate, onSaved, onMoved, getRoots, reopen }) {
  const title = root.querySelector('[data-panel-title]');
  const panel = root.querySelector('[data-panel-body]');
  const filter = root.querySelector('[data-panel-filter]');
  const lane = createRequestLane();
  let current = null;
  let editing = null;
  let updatedName = '';
  let rows = [];

  function setTitle(name, type, record) {
    title.replaceChildren(...(type ? [typeIcon(type)] : []), element('h1', '', name));
    if (!record) return;
    const copy = button('', { iconName: 'copy', className: 'icon-button object-title__copy', ariaLabel: 'Copy distinguished name' });
    copy.title = 'Copy distinguished name';
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(record.dn); notify.success('Distinguished name copied'); }
      catch { notify.error('Clipboard unavailable. Copy the distinguished name from the attributes.'); }
    });
    title.append(copy);
    const control = attribute(record, 'userAccountControl');
    if (values(control).length) {
      const disabled = accountDisabled(control);
      title.append(element('span', disabled ? 'state state--disabled' : 'state', disabled ? 'Disabled' : 'Enabled'));
    }
  }

  function canLeave() {
    if (guard.busy()) { notify.info('Wait for the current change to finish.'); return false; }
    if (editing) {
      notify.info('Save or cancel the attribute edit first.');
      editing.focus();
      return false;
    }
    return true;
  }

  function renderValues(cell, value) {
    const list = values(value);
    if (!list.length) { cell.append(element('span', 'value value--empty', 'Not set')); return; }
    const draw = (items) => {
      for (const item of items) {
        const text = textValue(item);
        if (typeof item === 'string' && isDN(text)) {
          const link = element('button', 'value value--dn');
          link.type = 'button';
          dnText(link, text);
          link.addEventListener('click', () => onNavigate(text));
          cell.append(link);
        } else {
          const time = typeof item === 'string' ? readableTime(text) : null;
          cell.append(time ? timeValue(text, time) : element('span', 'value', text));
        }
      }
    };
    draw(list.slice(0, VALUE_PREVIEW));
    if (list.length > VALUE_PREVIEW) {
      const more = element('button', 'value-more', `Show all ${list.length} values`);
      more.type = 'button';
      more.addEventListener('click', () => { more.remove(); draw(list.slice(VALUE_PREVIEW)); });
      cell.append(more);
    }
  }

  async function commit({ attribute, operation, fieldValues, form, fail }) {
    if (!guard.begin()) return;
    setBusy(form, true);
    try {
      await directory.edit(current.dn, scope(current.dn), operation, attribute, fieldValues);
    } catch (error) {
      setBusy(form, false);
      fail(error.message);
      return;
    } finally {
      guard.end();
    }
    editing = null;
    notify.success(operation === 'clear' ? `Cleared ${attribute}` : `Saved ${attribute}`);
    updatedName = attribute.toLowerCase();
    await onSaved();
  }

  function edit(tr, name, value) {
    if (!canLeave()) return;
    const editor = createValueEditor({
      name,
      values: name ? editableText(value) : [],
      onCancel: () => { editing = null; render(); },
      onSubmit: ({ attribute, values: fieldValues, form, fail }) => commit({ attribute, operation: '_set', fieldValues, form, fail }),
      onClear: name ? ({ form, fail }) => commit({ attribute: name, operation: 'clear', fieldValues: [], form, fail }) : undefined,
    });
    editing = editor;
    tr.classList.add('is-editing');
    if (editor.nameField) tr.replaceChildren(cell('th', undefined, 'row'), element('td'), element('td', 'cell-actions'));
    if (editor.nameField) tr.firstChild.append(editor.nameField);
    tr.querySelector('td').replaceChildren(editor.form);
    editor.focus();
  }

  function cell(tag, text, scope) {
    const node = element(tag, '', text);
    if (scope) node.scope = scope;
    return node;
  }

  function row(name, value) {
    const tr = element('tr');
    tr.dataset.name = name.toLowerCase();
    if (tr.dataset.name === updatedName) tr.classList.add('is-updated');
    const valueCell = element('td');
    renderValues(valueCell, value);
    const actions = element('td', 'cell-actions');
    if (name.toLowerCase() === 'distinguishedname' && onMoved && !sameDN(current.dn, scope(current.dn) ?? '')) {
      const control = button('', { iconName: 'move', className: 'icon-button property-row__edit', ariaLabel: 'Move object' });
      control.title = 'Move object to another container';
      control.addEventListener('click', () => {
        if (canLeave()) moveObject({ record: current, directory, guard, getRoots, onMoved });
      });
      actions.append(control);
    } else if (editableField(name, value)) {
      const control = button('', { iconName: 'edit', className: 'icon-button property-row__edit', ariaLabel: `Edit ${name}` });
      control.addEventListener('click', () => edit(tr, name, value));
      tr.addEventListener('dblclick', (event) => { if (!event.target.closest('button, form')) edit(tr, name, value); });
      actions.append(control);
    }
    tr.append(cell('th', name, 'row'), valueCell, actions);
    return tr;
  }

  function applyFilter() {
    const text = filter.value.trim().toLowerCase();
    for (const tr of rows) tr.hidden = Boolean(text) && !tr.dataset.name.includes(text);
  }

  function render() {
    const table = element('table', 'property-grid');
    const columns = element('colgroup');
    columns.append(element('col', 'property-grid__name'), element('col'), element('col', 'property-grid__actions'));
    const head = element('thead');
    const headRow = element('tr');
    const actionsHeader = cell('th', undefined, 'col');
    actionsHeader.append(element('span', 'visually-hidden', 'Actions'));
    headRow.append(cell('th', 'Attribute', 'col'), cell('th', 'Value', 'col'), actionsHeader);
    head.append(headRow);
    const body = element('tbody');
    const names = Object.keys(current.attributes).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    rows = names.map((name) => row(name, current.attributes[name]));
    updatedName = '';
    body.append(...rows);
    const foot = element('tfoot');
    const addRow = element('tr');
    const addCell = element('td');
    addCell.colSpan = 3;
    const add = button('Add attribute', { iconName: 'plus', className: 'link-button' });
    add.addEventListener('click', () => edit(addRow, '', []));
    addCell.append(add);
    addRow.append(addCell);
    foot.append(addRow);
    table.append(columns, head, body, foot);
    panel.replaceChildren(table);
    applyFilter();
  }

  function message(heading, text, retry) {
    const box = element('div', 'panel-message');
    box.append(element('h2', '', heading), element('p', '', text));
    if (retry) {
      const action = button('Retry', { iconName: 'refresh' });
      action.addEventListener('click', retry);
      box.append(action);
    }
    panel.replaceChildren(box);
  }

  function skeleton() {
    const box = element('div', 'skeleton');
    box.setAttribute('aria-hidden', 'true');
    for (let index = 0; index < 9; index += 1) box.append(element('span'));
    panel.replaceChildren(box);
  }

  filter.addEventListener('input', applyFilter);
  filter.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && filter.value) { event.preventDefault(); filter.value = ''; applyFilter(); }
  });

  async function open(dn, { fresh = false } = {}) {
    const signal = lane.next();
    current = null;
    editing = null;
    filter.disabled = true;
    status.idle('');
    setTitle(dnLabel(dn));
    panel.replaceChildren();
    const finishLoading = beginLoading(panel, { signal, onDelay: skeleton });
    try {
      const result = await directory.record(dn, { signal, fresh });
      if (signal.aborted) return null;
      current = result;
      setTitle(recordName(result), objectType(result), result);
      filter.disabled = false;
      render();
      status.idle(summary(result));
      return result;
    } catch (error) {
      if (signal.aborted) return null;
      setTitle(dnLabel(dn));
      message('Cannot load this object', error.message, () => (reopen ?? open)(dn, { fresh: true }));
      return null;
    } finally {
      if (!signal.aborted) finishLoading();
    }
  }

  return {
    open,
    canLeave,
    current: () => current,
    fail(heading, error, retry) {
      lane.cancel();
      current = null;
      title.replaceChildren();
      filter.disabled = true;
      message(heading, error.message, retry);
    },
  };
}
