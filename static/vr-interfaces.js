/* Shared configured-interface selectors for Virtual Router dialogs. */
async function vrLoadInterfaceChoices(id, router, selected = [], members = false) {
  const select = document.getElementById(id);
  select.disabled = true;
  select.replaceChildren();
  const response = await consoleRequest('/api/network/virtual-router-interfaces');
  const rows = response.interfaces || [];
  const add = (value, label, chosen, disabled = false) => {
    const option = document.createElement('option');
    option.value = value; option.textContent = label;
    option.selected = chosen; option.disabled = disabled; select.appendChild(option);
  };
  if (!members) add('', 'Automatic — resolve next hop', selected.length === 0 || !selected[0]);
  const known = new Set();
  for (const row of rows) {
    const matches = selected.filter(name => name === row.name || name === row.alias);
    const value = matches[0] || row.name;
    known.add(row.name); if (row.alias) known.add(row.alias);
    const eligible = row.virtual_router === router || (members && row.virtual_router === 'default');
    const label = row.name + (row.addresses.length ? ' · ' + row.addresses.join(', ') : '') +
      (eligible ? '' : ' · assigned to ' + row.virtual_router);
    add(value, label, matches.length > 0 || (members && router === 'default' && eligible), !eligible);
  }
  // Never silently clear an existing route/member when inventory changes.
  for (const value of selected.filter(value => value && !known.has(value))) {
    add(value, value + ' · not in configured Layer 3 inventory', true);
  }
  select.disabled = members && router === 'default';
  return rows;
}

function vrRouteRow(route, name) {
  return `<tr><td class="mono">${_escSP(route.dest_cidr || '')}</td><td class="mono">${_escSP(route.next_hop || 'On-link')}</td>` +
    `<td>${_escSP(route.dev || 'Automatic')}</td><td>${_escSP(route.metric ?? 0)}</td><td>` +
    `<button class="btn btn-xs" data-vr="${_escSP(name)}" data-route="${_escSP(String(route.id))}" onclick="editVRoute(this.dataset.vr,this.dataset.route)">Edit</button> ` +
    `<button class="btn btn-xs btn-danger" data-vr="${_escSP(name)}" data-route="${_escSP(String(route.id))}" onclick="deleteVRoute(this.dataset.vr,this.dataset.route)">Delete</button></td></tr>`;
}

async function editVRoute(name, id) {
  const result = await consoleRequest('/api/network/virtual-routers/' + encodeURIComponent(name) + '/routes');
  const route = result.routes.find(row => String(row.id) === String(id));
  if (!route) throw new Error('Route changed or was removed; refresh the router.');
  await openVRouteModal(name, route);
}

async function refreshVrRouteViews(name) {
  await loadVirtualRouters();
  if (document.getElementById('vrr-name')?.value === name) await loadVrrStatic(name);
  if (document.getElementById('vr-routes-' + name)) await loadVRRoutes(name);
}
