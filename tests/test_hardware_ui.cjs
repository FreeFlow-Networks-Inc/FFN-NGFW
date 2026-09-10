// SPDX-License-Identifier: GPL-2.0-or-later
// Exercise the real renderer with partial, specialized and legacy inventories.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
const script = html.slice(html.indexOf('async function loadHardware('), html.indexOf('async function renderDashSystemHealth('));
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));

async function render(data) {
  const body = {innerHTML: ''};
  const context = vm.createContext({document: {getElementById: () => body},
                                   api: async () => data, _escSP: escape});
  vm.runInContext(script, context);
  await context.loadHardware(false);
  return body.innerHTML;
}

(async () => {
  const partial = await render({status: 'partial', diagnostics: [{section: 'pci', message: '<unsafe>', source: '/sys'}],
    specialized: {octeon: {present: true, host_cpu: true, evidence: [{source: '/proc/cpuinfo', value: 'OCTEON III'}]}},
    nics: [{name: 'dpdk0', kind: 'dpdk-bound', speed_mbps: 0, numa_node: 3, iommu_group: 17}]});
  assert.ok(partial.includes('Inventory partial'));
  assert.ok(partial.includes('&lt;unsafe&gt;'));
  assert.ok(!partial.includes('<unsafe>'));
  assert.ok(partial.includes('OCTEON host CPU / SoC'));
  assert.ok(partial.includes('<th>NUMA</th><th>IOMMU</th>'));
  assert.ok(partial.includes('<td>3</td>'));
  const legacy = await render({dpu: {present: true, devices: [{type: 'Legacy DPU', control_channels: {rshim: true}}]}});
  assert.ok(legacy.includes('Legacy DPU'));
  const modern = await render({dpu: {present: true, devices: [{type: 'BlueField-3'}], control_channels: {rshim: ['/dev/rshim0']}}});
  assert.ok(modern.includes('not mapped to individual cards'));
  assert.ok(modern.includes('/dev/rshim0'));
  const empty = await render({});
  assert.ok(empty.includes('None detected'));
  assert.ok(!empty.includes('undefined'));
  const management = await render({cpu_role: {role: 'management', reason: 'FPGA detected'},
    cpu: {cores_logical: 8, isolated_cpus: '2-7'}, accelerators: [{kind: 'fpga', bus: 'platform',
      managers: [{name: 'fpga0', state: 'operating'}]}]});
  assert.ok(management.includes('No host dataplane cores reserved'));
  assert.ok(management.includes('Isolation mismatch'));
  assert.ok(management.includes('fpga0: operating'));

  const body = {innerHTML: ''};
  const context = vm.createContext({document: {getElementById: () => body}, _escSP: escape});
  vm.runInContext(script + html.slice(html.indexOf('async function loadCpuPlanes('), html.indexOf('function _dpDot(')), context);
  const ports = context.detectedPortsHTML({status: 'partial', nics: [
    {name: 'eth0', kind: 'physical', state: 'down', speed_mbps: 1000, driver: 'igb'},
    {name: '(dpdk)0000:03:00.0', kind: 'dpdk-bound', state: 'dpdk', speed_mbps: 0, driver: 'vfio-pci'},
    {name: '<unsafe>', kind: 'virtual', state: 'unknown'}]},
    [{name: 'ethernet1/1', diag_name: 'swp1', live: true, link: true, speed_gbps: 100}],
    [{name: 'swp1'}, {name: 'eth0'}, {name: 'qsfp0', type: 'fpga', link_up: false}], {eth0: 'management'});
  assert.ok(ports.includes('Detected ports and interfaces (5)'));
  assert.ok(ports.includes('100 Gbps'));
  assert.ok(ports.includes('>Down<'));
  assert.ok(ports.includes('>Unknown<'));
  assert.ok(!ports.includes('>0 Gbps<'));
  assert.ok(ports.includes('vfio-pci'));
  assert.ok(ports.includes('&lt;unsafe&gt;') && !ports.includes('<unsafe>'));
  assert.ok(ports.includes('inventory is incomplete'));
  context.api = async () => ({available: true, cpu_role: 'management', ncpu: 8,
    planes: {mgmt: '0-7', ctrl: '', data: ''}, isolated: '2-7'});
  await context.loadCpuPlanes();
  assert.ok(body.innerHTML.includes('not assigned on host'));
  assert.ok(body.innerHTML.includes('no host packet workers'));
  assert.ok(body.innerHTML.includes('Isolation mismatch'));
  context.api = async () => null;
  await context.loadCpuPlanes();
  assert.ok(body.innerHTML.includes('Hardware discovery must complete'));

  vm.runInContext(html.slice(html.indexOf('async function loadInterfacesFull('), html.indexOf('function _ifaceRowHTML(')), context);
  const responses = {
    '/api/system/interfaces': {interfaces: [{name: 'eth0', link_up: true}]},
    '/api/interfaces/aliases': {aliases: [{pan_name: 'ethernet1/99', linux_name: 'eth0'}]},
    '/api/interfaces/enriched': {faceplate: [{name: 'ethernet1/1', live: true, link: false}], ethernet: []},
    '/api/system/hardware?refresh=1': {status: 'ok', nics: [{name: 'eth0', state: 'up'}]},
  };
  const elements = {};
  context.document.getElementById = id => elements[id] ||= {innerHTML: ''};
  context.api = async url => responses[url] || {};
  context._ifaceActiveKind = 'ethernet';
  context._renderConfiguredAE = () => {};
  context._ifaceRowHTML = row => `<tr>${row.name}:${row.link_state}</tr>`;
  await context.loadInterfacesFull(true);
  assert.ok(elements['iface-detected'].innerHTML.includes('eth0'));
  assert.equal(elements['iface-grid-body'].innerHTML, '<tr>ethernet1/1:false</tr>');
  responses['/api/interfaces/enriched'] = {ethernet: []};
  await context.loadInterfacesFull(true);
  assert.equal(elements['iface-grid-body'].innerHTML, '<tr>ethernet1/99:true</tr>');

  // A slow prior refresh must never overwrite a newer inventory.
  context.document.getElementById = () => body;
  const pending = [];
  context.api = url => new Promise(resolve => pending.push({url, resolve}));
  const first = context.loadHardware(false), second = context.loadHardware(true);
  assert.equal(pending[1].url, '/api/system/hardware?refresh=1');
  pending[1].resolve({system: {product: 'Newest inventory'}});
  await second;
  pending[0].resolve({system: {product: 'Stale inventory'}});
  await first;
  assert.ok(body.innerHTML.includes('Newest inventory') && !body.innerHTML.includes('Stale inventory'));
  console.log('Hardware, CPU roles, mixed ports, partial inventory, escaping and refresh ordering passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
