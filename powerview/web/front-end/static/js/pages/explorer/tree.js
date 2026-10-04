import { dnLabel, parentDN, sameDN, splitDN } from '../../core/dn.js';
import { objectType, recordName } from '../../core/directory.js';
import { element, icon } from '../../core/dom.js';
import { leave, restart } from '../../core/motion.js';
import { typeIcon } from '../../components/type-icon.js';
import { beginLoading } from '../../components/loading.js';

const PAGE_SIZE = 500;
const KEY_SELECT_DELAY = 140;
const SLOW_AFTER = 3000;

const key = (dn) => dn.toLowerCase();
const isWithin = (dn, ancestor) => sameDN(dn, ancestor) || key(dn).endsWith(`,${key(ancestor)}`);
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

function rootLabel(dn) {
  const parts = splitDN(dn);
  return parts.every((part) => /^dc=/i.test(part)) ? parts.map((part) => part.slice(3)).join('.') : dnLabel(dn);
}

export function createTree({ directory, onSelect }) {
  const tree = document.querySelector('#directory-tree');
  const filter = document.querySelector('#tree-filter');
  const emptyNote = element('li', 'tree-note', 'No loaded objects match');
  emptyNote.setAttribute('role', 'none');
  const nodes = new Map();
  let roots = [];
  let selected = null;
  let focusable = null;
  let generation = 0;
  let keyTimer;

  const query = () => filter.value.trim().toLocaleLowerCase();
  const nodeOf = (target) => nodes.get(key(target.closest('.tree-item')?.dataset.dn ?? ''));

  function paint(node) {
    const twisty = element('span', 'tree-twisty');
    twisty.append(icon('chevron-right'));
    node.line.replaceChildren(twisty, typeIcon(node.type), element('span', 'tree-label', node.label));
    node.item.setAttribute('aria-label', node.label);
  }

  function createNode(dn, label, type, level) {
    const item = element('li', 'tree-item');
    item.setAttribute('role', 'treeitem');
    item.setAttribute('aria-level', String(level));
    item.setAttribute('aria-selected', 'false');
    item.tabIndex = -1;
    item.dataset.dn = dn;
    const line = element('div', 'tree-line');
    line.title = dn;
    item.append(line);
    const node = {
      dn, label, type, level, item, line, group: null, children: null, expanded: false, opening: false,
      loading: false, wait: null, controller: null, error: null, limit: PAGE_SIZE,
    };
    paint(node);
    sync(node);
    nodes.set(key(dn), node);
    return node;
  }

  function forget(dn) {
    for (const [nodeKey, node] of nodes) {
      if (!isWithin(node.dn, dn)) continue;
      if (node === selected) selected = null;
      if (node === focusable) focusable = null;
      nodes.delete(nodeKey);
    }
  }

  function note(text, action, handler, tone = '') {
    const line = element('li', `tree-note ${tone}`.trim(), text);
    line.setAttribute('role', 'none');
    if (action) {
      const control = element('button', '', action);
      control.type = 'button';
      control.addEventListener('click', handler);
      line.append(control);
    }
    return line;
  }

  function waitNote(node) {
    const slow = node.wait === 'slow';
    return note(slow ? 'Still loading…' : 'Loading…', slow && 'Cancel', () => { collapse(node); focus(node); });
  }

  function sync(node) {
    const searching = Boolean(query());
    const open = node.expanded || (searching && node.children?.length > 0);
    const expandable = node.children === null || node.children.length > 0 || Boolean(node.error);
    if (expandable) node.item.setAttribute('aria-expanded', String(open));
    else node.item.removeAttribute('aria-expanded');
    node.group?.remove();
    node.group = null;
    if (!open) return;
    const group = element('ul', 'tree-group');
    group.setAttribute('role', 'group');
    if (node.error) group.append(note(node.error.message, 'Retry', () => expand(node, true), 'tree-note--error'));
    if (node.wait && node.children === null) group.append(waitNote(node));
    const children = node.children ?? [];
    const visible = searching ? children : children.slice(0, node.limit);
    for (const child of visible) group.append(child.item);
    if (!searching && children.length > node.limit) {
      const remaining = children.length - node.limit;
      group.append(note(`${remaining} more`, `Show ${Math.min(PAGE_SIZE, remaining)}`, () => { node.limit += PAGE_SIZE; sync(node); }));
    }
    if (!group.childElementCount) return;
    if (node.opening) group.classList.add('is-entering');
    node.opening = Boolean(node.wait) && node.children === null;
    node.group = group;
    node.item.append(group);
  }

  async function load(node, fresh = false) {
    if (node.pending) return node.pending;
    if (node.children && !fresh) return undefined;
    const current = generation;
    const known = node.children !== null;
    const arrived = [];
    const controller = new AbortController();
    const waiting = (state) => () => { node.wait = state; sync(node); };
    const finishLoading = beginLoading(node.item, { signal: controller.signal, onDelay: waiting('loading') });
    const slowTimer = setTimeout(waiting('slow'), SLOW_AFTER);
    node.controller = controller;
    node.loading = true;
    node.error = null;
    node.pending = (async () => {
      try {
        const records = await directory.children(node.dn, { fresh, signal: controller.signal });
        if (current !== generation) return;
        const stale = new Set((node.children ?? []).map((child) => key(child.dn)));
        node.children = records
          .map((record) => ({ dn: record.dn, label: recordName(record), type: objectType(record) }))
          .sort((a, b) => collator.compare(a.label, b.label))
          .map(({ dn, label, type }) => {
            stale.delete(key(dn));
            const existing = nodes.get(key(dn));
            if (!existing) {
              const child = createNode(dn, label, type, node.level + 1);
              if (known) arrived.push(child);
              return child;
            }
            if (existing.label !== label || existing.type !== type) {
              existing.label = label;
              existing.type = type;
              paint(existing);
            }
            return existing;
          });
        for (const dn of stale) forget(dn);
      } catch (error) {
        if (current === generation && !controller.signal.aborted) node.error = error;
      } finally {
        clearTimeout(slowTimer);
        finishLoading();
        node.pending = null;
        node.controller = null;
        node.wait = null;
        if (current === generation) {
          node.loading = false;
          sync(node);
          if (query()) applyFilter();
          for (const child of arrived) child.line.classList.add('is-arrived');
        }
      }
    })();
    return node.pending;
  }

  async function expand(node, fresh = false) {
    if (!node.expanded) node.opening = true;
    node.expanded = true;
    sync(node);
    await load(node, fresh);
  }

  function collapse(node) {
    if (node.children === null) node.controller?.abort();
    node.expanded = false;
    node.opening = false;
    sync(node);
    if (selected && selected !== node && isWithin(selected.dn, node.dn)) focus(node);
  }

  function markSelected(node) {
    selected?.item.setAttribute('aria-selected', 'false');
    selected = node;
    node?.item.setAttribute('aria-selected', 'true');
  }

  function focus(node, { move = true } = {}) {
    if (focusable) focusable.item.tabIndex = -1;
    focusable = node;
    node.item.tabIndex = 0;
    if (move) node.item.focus({ preventScroll: true });
    node.line.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  function activate(node, { expandNode = false } = {}) {
    clearTimeout(keyTimer);
    if (onSelect(node.dn) === false) return;
    markSelected(node);
    focus(node);
    if (expandNode && !node.expanded) expand(node);
  }

  function visibleItems() {
    return [...tree.querySelectorAll('.tree-item')].filter((item) => !item.closest('[hidden]'));
  }

  function applyFilter() {
    const text = query();
    const visit = (node) => {
      const childMatch = (node.children ?? []).map(visit).some(Boolean);
      const match = !text || node.label.toLocaleLowerCase().includes(text) || childMatch;
      node.item.hidden = !match;
      return match;
    };
    for (const node of nodes.values()) sync(node);
    const anyMatch = roots.map(visit).some(Boolean);
    emptyNote.remove();
    if (text && !anyMatch) tree.append(emptyNote);
  }

  tree.addEventListener('click', (event) => {
    if (event.target.closest('.tree-note')) return;
    const node = nodeOf(event.target);
    if (!node) return;
    if (event.target.closest('.tree-twisty')) {
      focus(node);
      if (node.expanded) collapse(node);
      else expand(node);
      return;
    }
    activate(node, { expandNode: true });
  });

  tree.addEventListener('keydown', (event) => {
    if (!event.target.matches('.tree-item')) return;
    const node = nodeOf(event.target);
    const items = visibleItems();
    const index = items.indexOf(node.item);
    const step = (target) => {
      if (!target) return;
      const next = nodeOf(target);
      if (onSelect(next.dn, { preview: true }) === false) return;
      markSelected(next);
      focus(next);
      clearTimeout(keyTimer);
      keyTimer = setTimeout(() => onSelect(next.dn), KEY_SELECT_DELAY);
    };
    switch (event.key) {
      case 'ArrowDown': step(items[index + 1]); break;
      case 'ArrowUp': step(items[index - 1]); break;
      case 'Home': step(items[0]); break;
      case 'End': step(items.at(-1)); break;
      case 'ArrowRight':
        if (node.item.getAttribute('aria-expanded') === 'false') expand(node);
        else step(node.group?.querySelector('.tree-item:not([hidden])'));
        break;
      case 'ArrowLeft':
        if (node.item.getAttribute('aria-expanded') === 'true' && node.expanded) collapse(node);
        else step(node.item.parentElement.closest('.tree-item'));
        break;
      case 'Enter':
        activate(node);
        if (node.expanded) collapse(node); else expand(node);
        break;
      default: return;
    }
    event.preventDefault();
  });

  tree.addEventListener('animationend', ({ target }) => target.classList.remove('is-entering', 'is-arrived'));

  filter.addEventListener('input', applyFilter);
  filter.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && filter.value) { filter.value = ''; applyFilter(); event.stopPropagation(); }
    if (event.key === 'ArrowDown') { event.preventDefault(); (focusable ?? roots[0])?.item.focus(); }
  });

  return {
    setRoots(dns) {
      generation += 1;
      nodes.clear();
      selected = null;
      roots = dns.map((dn) => createNode(dn, rootLabel(dn), 'domain', 1));
      tree.replaceChildren(...roots.map((node) => node.item));
      if (roots[0]) focus(roots[0], { move: false });
    },

    async reveal(dn) {
      const current = generation;
      const root = [...roots].sort((a, b) => b.dn.length - a.dn.length).find((node) => isWithin(dn, node.dn));
      if (!root) { markSelected(null); return; }
      const parts = splitDN(dn);
      const chain = parts.map((_, index) => parts.slice(index).join(','))
        .filter((path) => isWithin(path, root.dn) && !sameDN(path, root.dn))
        .reverse();
      let node = root;
      for (const path of chain) {
        if (!node.expanded || !node.children) await expand(node);
        if (current !== generation) return;
        const index = (node.children ?? []).findIndex((child) => sameDN(child.dn, path));
        if (index < 0) break;
        if (index >= node.limit) { node.limit = Math.ceil((index + 1) / PAGE_SIZE) * PAGE_SIZE; sync(node); }
        node = node.children[index];
      }
      if (!sameDN(node.dn, dn)) { markSelected(null); return; }
      markSelected(node);
      focus(node, { move: false });
    },

    async expand(dn) {
      const node = nodes.get(key(dn));
      if (node) await expand(node);
    },

    async refresh(dn) {
      const node = nodes.get(key(dn));
      if (node?.children) await load(node, true);
    },

    highlight(dn) {
      const node = nodes.get(key(dn));
      if (!node?.item.isConnected) return;
      restart(node.line, 'is-arrived');
      node.line.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    },

    async dismiss(dn) {
      const node = nodes.get(key(dn));
      if (!node?.item.isConnected) return;
      node.item.style.setProperty('--leave-height', `${node.item.offsetHeight}px`);
      await leave(node.item);
      const parent = nodes.get(key(parentDN(dn)));
      forget(dn);
      if (!parent?.children) return;
      parent.children = parent.children.filter((child) => child !== node);
      sync(parent);
    },
  };
}
