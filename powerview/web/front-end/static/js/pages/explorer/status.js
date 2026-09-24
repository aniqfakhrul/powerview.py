const CLEAR_AFTER = 6000;

export function createStatus() {
  const message = document.querySelector('#status-message');
  const domain = document.querySelector('#status-domain');
  let baseline = '';
  let active = '';
  let timer;

  function paint(tone = '') {
    message.textContent = active || baseline;
    message.dataset.tone = active ? tone : '';
  }

  function show(text, tone = '') {
    clearTimeout(timer);
    active = text;
    paint(tone);
    if (text && tone !== 'error') timer = setTimeout(() => show(''), CLEAR_AFTER);
  }

  return {
    info: (text) => show(text),
    success: (text) => show(text, 'success'),
    error: (text) => show(text, 'error'),
    clear: () => show(''),
    idle(text) {
      baseline = text;
      if (!active) paint();
    },
    domain(text) { domain.textContent = text; },
  };
}
