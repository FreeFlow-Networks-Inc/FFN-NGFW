/* Shared stacking for legacy and dynamically created console dialogs. */
(() => {
  'use strict';
  const stack = [], blocked = new Map();
  const positions = new WeakMap();
  let drag = null;
  let previousFocus = null, currentFocus = document.activeElement;
  const visible = el => el.isConnected && el.classList.contains('show');
  const top = () => stack[stack.length - 1]?.el;
  const controls = el => [...el.querySelectorAll('button,input,select,textarea,a[href],[tabindex]')]
    .filter(node => !node.disabled && node.tabIndex >= 0 && !node.closest('[inert]') && node.getClientRects().length);
  const focus = el => {
    if (!el) return;
    if (!el.hasAttribute('tabindex')) el.tabIndex = -1;
    (controls(el)[0] || el).focus({preventScroll:true});
  };
  function sync(records = []) {
    const prior = top();
    let restore = null;
    for (let i = stack.length - 1; i >= 0; --i) {
      if (!visible(stack[i].el)) {
        const entry = stack.splice(i, 1)[0];
        entry.el.style.zIndex = entry.zIndex;
        const dialog = entry.el.querySelector('.modal');
        if (dialog && positions.has(dialog)) {
          Object.assign(dialog.style, positions.get(dialog));
          positions.delete(dialog);
        }
        if (drag?.overlay === entry.el) drag = null;
        restore = entry.opener;
      }
    }
    // Attribute mutation order is the opening order, independent of DOM order.
    const candidates = records.filter(r => r.type === 'attributes').map(r => r.target);
    candidates.push(...document.querySelectorAll('.modal-overlay.show'));
    for (const el of candidates) {
      if (!el.matches('.modal-overlay') || !visible(el) || stack.some(s => s.el === el)) continue;
      stack.push({el, zIndex:el.style.zIndex,
        opener:el.contains(document.activeElement) ? previousFocus : document.activeElement});
    }
    for (const [el, wasInert] of blocked) el.inert = wasInert;
    blocked.clear();
    stack.forEach((entry, index) => { entry.el.style.zIndex = String(1000 + index); });
    const active = top();
    // Disable siblings along the active dialog's ancestry. This also handles
    // editors inside #app without making their own ancestors inert.
    for (let node = active; node && node !== document.body; node = node.parentElement) {
      for (const sibling of node.parentElement?.children || []) {
        if (sibling === node || /^(SCRIPT|STYLE|LINK)$/.test(sibling.tagName)) continue;
        blocked.set(sibling, sibling.inert);
        sibling.inert = true;
      }
    }
    document.body.classList.toggle('modal-active', !!active);
    if (active !== prior) {
      if (restore?.isConnected && !restore.closest('[inert]') && (!active || active.contains(restore))) {
        restore.focus({preventScroll:true});
      } else if (active && !active.contains(document.activeElement)) focus(active);
    }
  }
  const observer = new MutationObserver(records => {
    if (records.some(r => r.type === 'childList' || r.target.matches('.modal-overlay'))) sync(records);
  });
  observer.observe(document.body, {subtree:true, childList:true, attributes:true, attributeFilter:['class']});
  document.addEventListener('focusin', event => {
    previousFocus = currentFocus;
    currentFocus = event.target;
    const active = top();
    if (active && visible(active) && !active.contains(event.target)) focus(active);
  });
  document.addEventListener('keydown', event => {
    const active = top();
    if (!active || !visible(active)) return;
    if (event.key === 'Escape' && !event.isComposing) {
      event.preventDefault(); event.stopImmediatePropagation();
      active.classList.remove('show');
      sync();
    } else if (event.key === 'Tab') {
      const list = controls(active), first = list[0], last = list[list.length - 1];
      if (!first || (event.shiftKey ? document.activeElement === first : document.activeElement === last)
          || !active.contains(document.activeElement)) {
        event.preventDefault(); event.stopImmediatePropagation();
        if (first) (event.shiftKey ? last : first).focus(); else focus(active);
      }
    }
  }, true);
  document.addEventListener('click', event => {
    if (event.target === top()) {
      event.preventDefault(); event.stopImmediatePropagation();
      event.target.classList.remove('show');
      sync();
    }
  }, true);
  function move(dialog, x, y) {
    const rect = dialog.getBoundingClientRect();
    if (!positions.has(dialog)) positions.set(dialog, {
      position:dialog.style.position, left:dialog.style.left, top:dialog.style.top,
      margin:dialog.style.margin, width:dialog.style.width
    });
    Object.assign(dialog.style, {position:'fixed', margin:'0', width:rect.width + 'px',
      left:Math.max(12, Math.min(x, window.innerWidth - rect.width - 12)) + 'px',
      top:Math.max(12, Math.min(y, window.innerHeight - rect.height - 12)) + 'px'});
  }
  document.addEventListener('pointerdown', event => {
    const heading = event.target.closest('.modal h3, .modal-header');
    const dialog = heading?.closest('.modal'), overlay = dialog?.closest('.modal-overlay');
    if (!dialog || overlay !== top() || event.button !== 0
        || event.target.closest('button,input,select,textarea,a')) return;
    const rect = dialog.getBoundingClientRect();
    drag = {dialog, overlay, id:event.pointerId, dx:event.clientX - rect.left, dy:event.clientY - rect.top};
    heading.setPointerCapture(event.pointerId);
    event.preventDefault();
  });
  document.addEventListener('pointermove', event => {
    if (drag && event.pointerId === drag.id) move(drag.dialog, event.clientX - drag.dx, event.clientY - drag.dy);
  });
  for (const type of ['pointerup', 'pointercancel', 'lostpointercapture']) {
    document.addEventListener(type, () => { drag = null; });
  }
  window.addEventListener('resize', () => {
    for (const {el} of stack) {
      const dialog = el.querySelector('.modal');
      if (dialog && positions.has(dialog)) {
        const rect = dialog.getBoundingClientRect(); move(dialog, rect.left, rect.top);
      }
    }
  });
  sync();
})();
