export const settled = (node) => Promise.allSettled(node.getAnimations().map((animation) => animation.finished));

export function restart(node, className) {
  node.classList.remove(className);
  void node.offsetWidth;
  node.classList.add(className);
}

export async function leave(node, className = 'is-leaving') {
  node.inert = true;
  node.setAttribute('aria-hidden', 'true');
  node.classList.add(className);
  await settled(node);
  node.remove();
}
