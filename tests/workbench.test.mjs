import test from 'node:test';
import assert from 'node:assert/strict';
import { statusBucket, matchesFinding, scopePresentation, orderNavigationScopes, summarizeFindings, visibleTreeChecks, clusterParentScope, nextStatusFilter, summaryChipModel, statusFilterLabel, statusSelectOptions } from '../public/workbench.js';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { checkOwnerScope, canonicalGatewayName, gatewayIdentityKey, displayCellValue, gatewayTargetsForCheck } from '../public/finding-model.js';

test('member nesting resolves only its matching cluster and preserves orphans', () => {
  const scopes = ['CL (Cluster Object)', 'M1 (cluster member of: CL)', 'M2 (cluster member of: CL)', 'Orphan (cluster member of: missing)', 'Standalone'].map(title => ({title, section:'Gateways and clusters'}));
  assert.equal(clusterParentScope(scopes,scopes[1]),scopes[0]);
  assert.equal(clusterParentScope(scopes,scopes[2]),scopes[0]);
  assert.equal(clusterParentScope(scopes,scopes[3]),null);
  assert.equal(clusterParentScope(scopes,scopes[4]),null);
  assert.equal(clusterParentScope(scopes,{...scopes[1],section:'Categories'}),null);
});

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
  assert.deepEqual(scopePresentation('Policy and Management','Policy and Management'), {name:'Policy and Access',subtitle:'',kind:'policy'});
  assert.equal(scopePresentation('Policy and Management','Categories').kind,'category');
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
test('summary chips toggle one status bucket and total clears it', () => {
  assert.equal(nextStatusFilter('', 'action'), 'action');
  assert.equal(nextStatusFilter('action', 'action'), '');
  assert.equal(nextStatusFilter('action', 'total'), '');
  assert.equal(nextStatusFilter('review', 'pass'), 'pass');
  assert.equal(nextStatusFilter('manual', ''), '');
  const finding = {title: 'Allowed Hosts', category: 'Gaia', status: 'remediation-required', severity: 'high'};
  assert.equal(matchesFinding(finding, {status: nextStatusFilter('', 'action')}), true);
  assert.equal(matchesFinding({...finding, status: 'pass'}, {status: nextStatusFilter('', 'action')}), false);
});

test('only non-zero summary chips are interactive and pressed follows the active bucket', () => {
  const items = summarizeFindings([{status: 'remediation-required'}, {status: 'pass'}, {status: 'pass'}]);
  const idle = summaryChipModel(items, '');
  assert.equal(idle.find(chip => chip.key === 'total').pressed, true);
  assert.equal(idle.find(chip => chip.key === 'total').interactive, true);
  assert.equal(idle.find(chip => chip.key === 'action').interactive, true);
  assert.equal(idle.find(chip => chip.key === 'action').pressed, false);
  assert.equal(idle.find(chip => chip.key === 'review').interactive, false);
  assert.equal(idle.find(chip => chip.key === 'review').pressed, false);
  assert.equal(idle.find(chip => chip.key === 'unknown').interactive, false);
  const action = summaryChipModel(items, 'action');
  assert.equal(action.find(chip => chip.key === 'action').pressed, true);
  assert.equal(action.find(chip => chip.key === 'action').label, 'Remediation needed');
  assert.equal(action.find(chip => chip.key === 'total').pressed, false);
  assert.equal(action.find(chip => chip.key === 'pass').pressed, false);
});

test('status select display text uses summary strip labels and keeps bucket values', () => {
  const summary = summarizeFindings([
    {status: 'remediation-required'}, {status: 'needs-review'}, {status: 'manual'},
    {status: 'unknown'}, {status: 'pass'}, {status: 'reviewed'}, {status: 'informational'}
  ]);
  assert.deepEqual(statusSelectOptions().map(([value]) => value), ['', 'action', 'review', 'manual', 'unknown', 'pass', 'reviewed', 'informational']);
  for (const [value, label] of statusSelectOptions()) {
    if (!value) continue;
    assert.equal(label, summary.find(item => item.key === value).label);
    assert.equal(label, statusFilterLabel(value));
  }
  assert.equal(statusSelectOptions().find(([value]) => value === 'action')[1], 'Remediation needed');
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
