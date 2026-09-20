import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import * as model from '../public/finding-model.js';

const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
const server = await readFile(new URL('../server.js', import.meta.url), 'utf8');
const extract = (source, start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
const context = vm.createContext({ ...model, hardeningScan: {},
  rowMatchesTarget: () => false, readOnlyEvidenceRow: row => row,
  detailRowsForGateway: () => [], escapeHtml: value => String(value),
  renderEvidenceCell: () => '<td>Evidence</td>' });
vm.runInContext(extract(app, 'function hasTargetScopedGatewayAction(', 'function hierarchySummary(')
  + extract(app, 'function renderEvidenceTable(', 'function isCriticalSnmpUsmLine('), context);
const table = (name, type, any = false) => ({ title: `Management Name: ${name}`, columns: ['Type'], rows: [{Type:type}],
  targetSelection: {value:name, hasAnyAllowedClient:any, onlyAnyAllowedClient:any} });
const check = { id:'gaia.allowed-host-access', status:'unknown', collection:{status:'partial', errors:['fake device failed']},
  evidenceTables:[table('Odette', {value:'any', tone:'critical'}, true), table('GFG','ipv4 address'), table('fake','Lookup failed')] };

test('Infrastructure scopes status and collection to the displayed device', () => {
  const odette = context.checkForGateway(check, 'Odette', 3);
  assert.equal(odette.status, 'remediation-recommended');
  assert.equal(odette.collection.status, 'complete');
  assert.equal(odette.evidenceTables.length, 1);
  assert.equal(context.checkForGateway(check, 'GFG', 3).status, 'needs-review');
  assert.equal(context.checkForGateway(check, 'fake', 3).status, 'unknown');
});
test('Infrastructure replaces checkboxes with the exact target and safety flags; Categories retain selection', () => {
  const scoped = context.checkForGateway(check, 'Odette', 3);
  const html = context.renderEvidenceTables(scoped.evidenceTables, check.id);
  assert.doesNotMatch(html, /type="checkbox"|Select All Devices|Select device/);
  assert.match(html, /class="gaia-implicit-target" data-target-name="Odette"/);
  assert.match(html, /data-only-any="true"/);
  assert.doesNotMatch(html, /GFG|fake/);
  assert.match(context.renderEvidenceTables(check.evidenceTables, check.id), /Select All Devices/);
  context.hardeningScan = {moraMode:true};
  assert.doesNotMatch(context.renderEvidenceTables(scoped.evidenceTables, check.id), /gaia-implicit-target|type="checkbox"/);
  context.hardeningScan = {};
});
test('confirmed AnyHost survives partial collection and refresh evaluation', () => {
  const ctx = vm.createContext({appHistory:{reviews:new Map()}, makeCheck:value=>value,
    uniqueStrings:values=>[...new Set(values)],
    gaiaAllowedClientRowsAllowAny:rows=>rows.some(row=>model.displayCellValue(row.Type)==='any')});
  vm.runInContext(extract(server, 'function evaluateGaiaAllowedHostAccess(', 'function evaluateGaiaAdministratorSettings('), ctx);
  assert.equal(ctx.evaluateGaiaAllowedHostAccess({ok:false, errors:['fake'], evidenceTables:check.evidenceTables}, {id:'test'}).status, 'remediation-recommended');
  assert.equal(ctx.evaluateGaiaAllowedHostAccess({ok:false, errors:['failed'], evidenceTables:[]}, {id:'test'}).status, 'unknown');
});
