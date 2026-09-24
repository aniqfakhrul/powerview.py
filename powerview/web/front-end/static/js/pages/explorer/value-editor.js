import { isDN } from '../../core/dn.js';
import { button, element } from './dom.js';

const ATTRIBUTE_NAME = /^[a-z][a-z0-9-]*$/i;

function valueInput(value, index) {
  const multiline = value.includes('\n');
  const input = element(multiline ? 'textarea' : 'input', isDN(value) ? 'text-input text-input--mono' : 'text-input');
  if (multiline) input.rows = Math.min(6, value.split('\n').length);
  else input.type = 'text';
  input.value = value;
  input.spellcheck = false;
  input.setAttribute('aria-label', `Value ${index + 1}`);
  return input;
}

export function createValueEditor({ name = '', values = [], onSubmit, onCancel, onClear }) {
  const isNew = !name;
  const form = element('form', 'value-editor');
  form.noValidate = true;
  const list = element('div', 'value-editor__list');
  const error = element('p', 'form-error');
  error.setAttribute('role', 'alert');
  error.hidden = true;

  let nameInput;
  if (isNew) {
    nameInput = element('input', 'text-input value-editor__name');
    nameInput.placeholder = 'Attribute name';
    nameInput.setAttribute('aria-label', 'Attribute name');
    nameInput.spellcheck = false;
    nameInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') { event.preventDefault(); form.requestSubmit(); }
      if (event.key === 'Escape') { event.preventDefault(); onCancel(); }
    });
  }

  function renumber() {
    [...list.querySelectorAll('.text-input')].forEach((input, index) => input.setAttribute('aria-label', `Value ${index + 1}`));
  }

  function addRow(value = '') {
    const row = element('div', 'value-editor__row');
    const input = valueInput(value, list.childElementCount);
    const remove = button('', { iconName: 'close', className: 'icon-button', ariaLabel: 'Remove value' });
    remove.addEventListener('click', () => {
      row.remove();
      if (!list.childElementCount) addRow();
      renumber();
      list.querySelector('.text-input')?.focus();
    });
    row.append(input, remove);
    list.append(row);
    return input;
  }

  for (const value of values.length ? values : ['']) addRow(value);

  const controls = element('div', 'value-editor__controls');
  const add = button('Add value', { iconName: 'plus', className: 'link-button' });
  add.addEventListener('click', () => addRow().focus());
  const save = element('button', 'button button--primary', 'Save');
  save.type = 'submit';
  const cancel = button('Cancel');
  cancel.addEventListener('click', onCancel);
  controls.append(add);
  if (onClear) {
    const clear = button('Clear attribute', { className: 'link-button value-editor__clear' });
    let armed;
    const disarm = () => { clearTimeout(armed); armed = null; clear.firstChild.textContent = 'Clear attribute'; };
    clear.addEventListener('click', () => {
      if (!armed) {
        clear.firstChild.textContent = 'Confirm clear';
        armed = setTimeout(disarm, 4000);
        return;
      }
      disarm();
      onClear({ form, fail });
    });
    clear.addEventListener('blur', disarm);
    controls.append(clear);
  }
  controls.append(cancel, save);
  form.append(list, controls, error);

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  form.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onCancel(); }
  });

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const attribute = isNew ? nameInput.value.trim() : name;
    const entered = [...list.querySelectorAll('.text-input')].map((input) => input.value).filter((value) => value !== '');
    if (!ATTRIBUTE_NAME.test(attribute)) { fail('Enter an LDAP attribute name, such as description.'); nameInput?.focus(); return; }
    if (!entered.length) { fail(onClear ? 'Enter a value, or clear the attribute.' : 'Enter at least one value.'); return; }
    fail('');
    onSubmit({ attribute, values: entered, form, fail });
  });

  return {
    form,
    nameField: nameInput,
    focus() { (nameInput ?? list.querySelector('.text-input')).focus(); },
  };
}
