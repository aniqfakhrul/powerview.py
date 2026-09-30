import { element } from '../core/dom.js';

export function createTabIndicator(tabList) {
  const indicator = element('span', 'panel-tabs__indicator');
  indicator.setAttribute('aria-hidden', 'true');
  tabList.append(indicator);
  let positioned = false;

  function sync(animate = false) {
    const tab = tabList.querySelector('[role="tab"][aria-selected="true"]');
    if (!tab?.offsetWidth) {
      indicator.hidden = true;
      positioned = false;
      return;
    }
    const style = getComputedStyle(tab);
    const left = parseFloat(style.paddingLeft);
    const width = tab.offsetWidth - left - parseFloat(style.paddingRight);
    indicator.hidden = false;
    indicator.classList.toggle('is-moving', animate && positioned);
    indicator.style.transform = `translateX(${tab.offsetLeft + left}px) scaleX(${width})`;
    tabList.classList.add('panel-tabs--indicator');
    positioned = true;
  }

  const observer = new ResizeObserver(() => sync());
  observer.observe(tabList);
  for (const tab of tabList.querySelectorAll('[role="tab"]')) observer.observe(tab);
  document.fonts?.ready.then(() => sync());
  return sync;
}
