import { element } from '../core/dom.js';

let dialog;

function build() {
  dialog = element('dialog', 'dialog');
  dialog.setAttribute('aria-labelledby', 'confirm-title');
  const form = element('form');
  form.method = 'dialog';
  const title = element('h2', 'dialog__title');
  title.id = 'confirm-title';
  const fields = element('div', 'dialog__fields');
  const footer = element('footer', 'dialog__footer');
  const cancel = element('button', 'button', 'Cancel');
  cancel.type = 'submit';
  cancel.value = 'cancel';
  const accept = element('button', 'button');
  accept.type = 'submit';
  accept.value = 'confirm';
  footer.append(cancel, accept);
  form.append(title, fields, footer);
  dialog.append(form);
  document.body.append(dialog);
  return { title, fields, cancel, accept };
}

export function confirmAction({ title, context, message, confirmLabel, danger = false }) {
  const parts = dialog ? {
    title: dialog.querySelector('.dialog__title'),
    fields: dialog.querySelector('.dialog__fields'),
    cancel: dialog.querySelector('button[value="cancel"]'),
    accept: dialog.querySelector('button[value="confirm"]'),
  } : build();
  const returnFocus = document.activeElement;
  parts.title.textContent = title;
  parts.fields.replaceChildren();
  if (context) parts.fields.append(element('p', 'dialog__context', context));
  if (message) parts.fields.append(element('p', '', message));
  parts.accept.textContent = confirmLabel;
  parts.accept.className = `button ${danger ? 'button--danger' : 'button--primary'}`;
  dialog.returnValue = '';
  dialog.showModal();
  (danger ? parts.cancel : parts.accept).focus();
  return new Promise((resolve) => {
    dialog.addEventListener('close', () => {
      if (returnFocus?.isConnected) returnFocus.focus();
      resolve(dialog.returnValue === 'confirm');
    }, { once: true });
  });
}
