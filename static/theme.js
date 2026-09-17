/* Apply before paint; preference is local to this browser, not firewall config. */
(() => {
  const key = 'ffn-console-theme';
  function apply(theme) {
    document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
    document.querySelectorAll('[data-theme-picker]').forEach(el => { el.value = theme; });
    if (window.Chart) {
      const color = getComputedStyle(document.documentElement).getPropertyValue('--text-dim').trim();
      const border = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();
      Chart.defaults.color = color; Chart.defaults.borderColor = border;
      for (const chart of Object.values(Chart.instances)) {
        for (const axis of Object.values(chart.options.scales || {})) {
          if (axis.ticks) axis.ticks.color = color;
          if (axis.title) axis.title.color = color;
          if (axis.grid) axis.grid.color = border;
        }
        if (chart.options.plugins?.legend?.labels) chart.options.plugins.legend.labels.color = color;
        chart.update('none');
      }
    }
  }
  let saved;
  try { saved = localStorage.getItem(key); } catch (_) { /* restricted storage */ }
  const preference = matchMedia('(prefers-color-scheme: dark)');
  apply(['light','dark'].includes(saved) ? saved : preference.matches ? 'dark' : 'light');
  document.addEventListener('DOMContentLoaded', () => {
    apply(document.documentElement.dataset.theme);
    document.querySelectorAll('[data-theme-picker]').forEach(el => el.addEventListener('change', () => {
      saved = el.value; apply(saved);
      try { localStorage.setItem(key, saved); } catch (_) { /* usable without persistence */ }
    }));
  });
  preference.addEventListener('change', e => { if (!saved) apply(e.matches ? 'dark' : 'light'); });
  window.ffnTheme = { refresh: () => apply(document.documentElement.dataset.theme) };
})();
