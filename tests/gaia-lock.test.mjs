import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../server.js', import.meta.url), 'utf8');
const extract = (start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
const helpers = extract('function statusDescriptionText(', 'function isRunScriptGatewayAccessFailure(')
  + extract('function gaiaOutputIncludesConfigLock(', 'function beginGaiaRemediationProgress(');
const runner = extract('async function runGaiaConfigCommandWithLockOverride(', 'async function addGaiaAllowedClientForTargets(');
const lockMessage = "CLINFR0771 Config lock is owned by admin. Use the command 'lock database override' to acquire the lock. CLINFR0519 Configuration lock present.";
const result = (ok, text, encodedOnly = false) => ({
  ok, data: { tasks: [{ status: ok ? 'succeeded' : 'failed', 'task-details': [{
    statusCode: ok ? 'succeeded' : 'failed',
    ...(!encodedOnly ? { statusDescription: text } : {}),
    responseMessage: Buffer.from(text).toString('base64')
  }] }] }, ...(!ok ? { error: { error: 'run-script failed; task IDs: test-task' } } : {})
});
function harness(responses = []) {
  const calls = [];
  const context = vm.createContext({ Buffer,
    normalizeToken: value => String(value).toLowerCase().replace(/[^a-z0-9]/g, ''),
    valuesForNormalizedKey: () => [], uidValues: value => [value],
    mdsRunScriptSession: session => session,
    updateGaiaRemediationProgress() {}, recordGaiaRemediationStep() {},
    sleep: async () => {}, enrichError: (error, fields) => Object.assign(error, fields),
    runScriptWithTaskDetails: async (session, body) => {
      calls.push(body);
      assert(responses.length, 'unexpected script retry');
      return responses.shift();
    }
  });
  vm.runInContext(helpers + runner, context);
  return { context, calls };
}
test('failed Gaia tasks retain lock diagnostics, including base64-only output', () => {
  const {context} = harness();
  for (const encodedOnly of [false, true]) {
    const failure = result(false, lockMessage, encodedOnly);
    assert.equal(context.gaiaOutputIncludesConfigLock(failure), true);
    assert.equal(context.responseMessageText(failure), lockMessage);
    assert.equal(failure.ok, false);
  }
  assert.equal(context.responseMessageText({ok:false}), '');
});
test('failed lock task invokes existing override then retries only the selected target', async () => {
  const {context,calls} = harness([result(false,lockMessage),result(true,'Lock acquired'),result(true,'Added')]);
  const outcome = await context.runGaiaConfigCommandWithLockOverride({}, {name:'LAB-MGMT'}, 'add client', 'add allowed-client host ipv4-address 192.0.2.12');
  assert.equal(outcome.retried,true);
  assert.equal(calls.length,3);
  assert.match(calls[1].script,/lock database override/);
  assert.equal(calls[0].script,calls[2].script);
  assert(calls.every(call => call.targets.length === 1 && call.targets[0] === 'LAB-MGMT'));
});
test('non-lock failure is not retried and surfaces its actual output with task ID', async () => {
  const {context,calls} = harness([result(false,'Permission denied')]);
  await assert.rejects(context.runGaiaConfigCommandWithLockOverride({}, {name:'LAB-MGMT'}, 'test','test'), /test-task: Permission denied/);
  assert.equal(calls.length,1);
});
test('failed override stops before another configuration attempt', async () => {
  const {context,calls} = harness([result(false,lockMessage),result(false,'Override denied')]);
  await assert.rejects(context.runGaiaConfigCommandWithLockOverride({}, {name:'LAB-MGMT'}, 'test','test'), /Override denied/);
  assert.equal(calls.length,2);
});
test('persistent locks exhaust bounded retries without claiming success', async () => {
  const responses=[result(false,lockMessage)];
  for(let i=0;i<3;i++) responses.push(result(true,'Lock acquired'),result(false,lockMessage));
  const {context,calls}=harness(responses);
  await assert.rejects(context.runGaiaConfigCommandWithLockOverride({}, {name:'LAB-MGMT'}, 'test','test'), /CLINFR0771/);
  assert.equal(calls.length,7);
});
