import test from 'node:test';
import assert from 'node:assert/strict';
import { statusBucket, matchesFinding } from '../public/workbench.js';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { checkOwnerScope, canonicalGatewayName, gatewayIdentityKey, displayCellValue, gatewayTargetsForCheck } from '../public/finding-model.js';

test('workbench preserves every status distinction and combines action aliases', () => {
  assert.equal(statusBucket('remediation-required'), 'action');
  assert.equal(statusBucket('remediation-recommended'), 'action');
  assert.equal(statusBucket('needs-review'), 'review');
  for (const status of ['manual', 'unknown', 'pass', 'reviewed', 'informational']) assert.equal(statusBucket(status), status);
});

test('all-domain hierarchy uses the selected domain inventory, not root metadata', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const nodes = [];
  const render = vm.runInNewContext(`${source.slice(source.indexOf('function isManagementObjectCheck('), source.indexOf('function updateResultViewButtons('))}; renderInfrastructureHierarchy`, {
    hardeningScan: {managementObjectName:'WRONG-ROOT',clusterTargets:['MEMBER-01']},
    checkOwnerScope, canonicalGatewayName, gatewayIdentityKey, displayCellValue, gatewayTargetsForCheck,
    orderInfrastructureChecks: checks => checks, renderCheckGroupsMarkup: () => '',
    checkForGateway: check => check, sharedCheckHasFindingForGateway: () => true,
    renderHierarchyNode: node => { nodes.push(node); return ''; }
  });
  const checks = [{id:'mgmt.firewall', category:'Management Plane Protection'},
    {id:'gaia.ntp', evidenceTable:{rows:[{Name:'CLUSTER-01'},{Name:'MEMBER-01'}]}}];
  render(checks,'domain:test',{managementObjectName:'MGMT-DOMAIN',clusterTargets:['CLUSTER-01'],clusterMemberships:[{memberName:'MEMBER-01',clusterName:'CLUSTER-01'}]});
  assert.ok(nodes.some(node => node.title === 'MGMT-DOMAIN'));
  assert.ok(nodes.some(node => node.title === 'MEMBER-01 (cluster member of: CLUSTER-01)'));
  assert.ok(!nodes.some(node => node.title === 'CLUSTER-01 (Cluster Object)'));
  assert.ok(!nodes.some(node => node.title === 'WRONG-ROOT'));
});
test('filters are conjunctive, case insensitive, and never mutate findings', () => {
  const finding = Object.freeze({ title: 'Allowed Hosts', category: 'Gaia OS Hardening', status: 'needs-review', severity: 'high' });
  assert.ok(matchesFinding(finding, {query: 'GAIA', status: 'review', severity: 'high'}));
  assert.ok(!matchesFinding(finding, {query: 'GAIA', status: 'action'}));
  assert.ok(!matchesFinding(finding, {severity: 'low'}));
  assert.ok(matchesFinding(finding, {}));
});

test('busy state locks the full workbench subtree, including non-button filters', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const attributes = {};
  const checksList = {setAttribute:(key, value) => attributes[key] = value};
  const button = {disabled:false,closest:()=>null};
  const setBusy = vm.runInNewContext(`${source.slice(source.indexOf('function setBusy('),source.indexOf('function setScanInProgress('))};setBusy`,{
    checksList, document:{querySelectorAll:()=>[button]}
  });
  setBusy(true);
  assert.equal(checksList.inert,true); assert.equal(attributes['aria-busy'],'true'); assert.equal(button.disabled,true);
  setBusy(false);
  assert.equal(checksList.inert,false); assert.equal(button.disabled,false);
});
