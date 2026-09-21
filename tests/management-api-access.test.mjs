import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../server.js', import.meta.url), 'utf8');
const context = vm.createContext({
  appHistory: { reviews: new Map([['mgmt.api-access', {sessionId:'test'}]]) },
  makeCheck: check => check,
  normalizeToken: value => String(value).toLowerCase().replace(/[^a-z0-9]/g, ''),
  trustedClientRows: clients => clients
});
vm.runInContext(source.slice(source.indexOf('function evaluateManagementApiAccess('), source.indexOf('async function administratorLastLogin(')), context);
const evaluate = (setting, objects = [], ok = true) => context.evaluateManagementApiAccess(
  {ok, data:{'accepted-api-calls-from':setting}}, {ok:true, objects}, {id:'test'});
const gui = 'all ip addresses that can be used for gui clients';

test('API GUI-client AnyHost is critical even if previously reviewed', () => {
  for (const client of [{name:'AnyHost',type:'any'}, {NAME:'AnyHost',TYPE:'ANY'}, {name:'custom',type:'any'}]) {
    const check = evaluate(gui, [client]);
    assert.equal(check.status, 'remediation-required');
    assert.equal(check.severity, 'high');
    assert.equal(check.detailTone, 'critical');
    assert.equal(check.remediation, null, 'do not offer a no-op API setting change');
    assert.equal(check.review, null);
    assert.match(check.details, /Restrict SmartConsole Trusted Clients/);
  }
});
test('unrestricted API setting retains its remediation', () => {
  const check = evaluate('all ip addresses');
  assert.equal(check.status, 'remediation-required');
  assert.equal(check.remediation.action, 'set-api-clients-gui-clients');
});
test('restricted settings do not inherit unrelated AnyHost exposure', () => {
  assert.equal(evaluate('this management server only', [{type:'any'}]).status, 'reviewed');
  assert.equal(evaluate(gui, [{name:'AnyHost',type:'ipv4 address'}]).status, 'reviewed');
  assert.equal(evaluate(gui, [], false).status, 'unknown');
});
