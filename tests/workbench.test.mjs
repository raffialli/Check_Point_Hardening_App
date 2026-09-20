import test from 'node:test';
import assert from 'node:assert/strict';
import { statusBucket, matchesFinding, scopePresentation, orderNavigationScopes, summarizeFindings, visibleTreeChecks } from '../public/workbench.js';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { checkOwnerScope, canonicalGatewayName, gatewayIdentityKey, displayCellValue, gatewayTargetsForCheck } from '../public/finding-model.js';

test('tree traversal searches object names and preserves scoped identities and filter order', () => {
  const checks = [{id:'same', title:'Allowed Hosts', category:'Gaia', status:'manual', severity:'high'}, {id:'other', title:'Logging', category:'Gaia', status:'pass', severity:'medium'}];
  const scopes = ['EDGE-A','EDGE-B'].map(title => ({key:title,title,section:'Gateways and clusters',checks}));
  assert.deepEqual(visibleTreeChecks(scopes,{query:'EDGE-B'}).map(e => e.scope.key), ['EDGE-B','EDGE-B']);
  assert.deepEqual(visibleTreeChecks(scopes,{status:'manual'}).map(e => [e.scope.key,e.check.id]), [['EDGE-A','same'],['EDGE-B','same']]);
  assert.equal(visibleTreeChecks(scopes,{query:'missing'}).length,0);
  assert.equal(visibleTreeChecks(scopes,{}).length,4);
});

test('summary accounts for informational and unfamiliar statuses without merging reviewed with passed', () => {
  const statuses = ['remediation-required', 'remediation-recommended', 'needs-review', 'manual', 'unknown', 'pass', 'reviewed', 'informational', 'not-applicable', undefined];
  const summary = summarizeFindings(statuses.map(status => ({status})));
  assert.equal(summary[0].count, 10);
  assert.equal(summary.slice(1).reduce((sum, item) => sum + item.count, 0), 10);
  assert.equal(summary.find(item => item.key === 'action').count, 2);
  assert.equal(summary.find(item => item.key === 'unknown').count, 2);
  for (const key of ['pass', 'reviewed', 'informational', 'not-applicable']) assert.equal(summary.find(item => item.key === key).count, 1);
});

test('workbench preserves every status distinction and combines action aliases', () => {
  assert.equal(statusBucket('remediation-required'), 'action');
  assert.equal(statusBucket('remediation-recommended'), 'action');
  assert.equal(statusBucket('needs-review'), 'review');
  for (const status of ['manual', 'unknown', 'pass', 'reviewed', 'informational']) assert.equal(statusBucket(status), status);
});

test('navigation separates object names from cluster relationship labels', () => {
  assert.deepEqual(scopePresentation('BRANCH-CL (Cluster Object)', 'Gateways and clusters'), {name:'BRANCH-CL',subtitle:'Cluster object',kind:'cluster'});
  assert.deepEqual(scopePresentation('BRANCH-A (cluster member of: BRANCH-CL)', 'Gateways and clusters'), {name:'BRANCH-A',subtitle:'Member of BRANCH-CL',kind:'gateway',parent:'BRANCH-CL'});
  assert.equal(scopePresentation('MGMT-LAB','Policy and Management').kind,'management');
});

test('cluster members follow their parent without dropping standalone or orphaned targets', () => {
  const scopes = ['Gateway Object SIC Status','BRANCH-A (cluster member of: BRANCH-CL)','BRANCH-CL (Cluster Object)','EDGE-01','MEMBER (cluster member of: unavailable)'].map(title=>({title,section:'Gateways and clusters'}));
  const ordered = orderNavigationScopes(scopes);
  assert.equal(ordered.length, scopes.length);
  assert.equal(ordered[1].title,'BRANCH-CL (Cluster Object)');
  assert.equal(ordered[2].title,'BRANCH-A (cluster member of: BRANCH-CL)');
  assert.equal(ordered[4].title,'MEMBER (cluster member of: unavailable)');
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
