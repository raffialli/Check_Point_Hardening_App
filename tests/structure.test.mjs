import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { collectPages, scopedCommandKey, collectionOutcome } from '../lib/collection.js';
import { beginOperation, finishOperation, trackRequest, assertNotCancelled } from '../lib/operations.js';
import { withFindingIdentity, gatewayTargetsForCheck, checkOwnerScope, collectionMessage } from '../public/finding-model.js';

test('paginates beyond rule 118 and merges object dictionaries', async () => {
  const offsets = [];
  const result = await collectPages(async ({ offset, limit }) => {
    offsets.push(offset);
    const end = Math.min(offset + limit, 120);
    return { ok: true, data: { rulebase: Array.from({length: end - offset}, (_, i) => ({uid: `rule-${offset+i+1}`})),
      total: 120, to: end, 'objects-dictionary': [{uid: `object-${offset}`}]} };
  }, { key: 'rulebase', limit: 50 });
  assert.deepEqual(offsets, [0, 50, 100]);
  assert.equal(result.data.rulebase[117].uid, 'rule-118');
  assert.equal(result.data['objects-dictionary'].length, 3);
  assert.equal(result.coverage.status, 'complete');
});

test('keeps earlier pages on failure and flags incomplete coverage', async () => {
  const result = await collectPages(async ({offset}) => offset === 0
    ? {ok: true, data: {objects: [{uid:'one'}], total:2, to:1}}
    : {ok: false, error:{error:'timeout'}});
  assert.equal(result.ok, false);
  assert.equal(result.objects, undefined);
  assert.equal(result.data.objects.length, 1);
  assert.equal(collectionOutcome(result).status, 'partial');
});

test('stops repeated pages and empty pages before the advertised total', async () => {
  const repeated = await collectPages(async () => ({ok:true,data:{objects:[{uid:'one'}],total:5}}));
  assert.equal(repeated.coverage.status, 'partial');
  assert.equal(repeated.data.objects.length, 1);
  const empty = await collectPages(async () => ({ok:true,data:{objects:[],total:5}}));
  assert.equal(empty.ok, false);
});

test('uses API to offsets for section-wrapped rulebases', async () => {
  const offsets=[];
  const result=await collectPages(async ({offset}) => {
    offsets.push(offset);
    return {ok:true,data:{rulebase:[{uid:`section-${offset}`}],total:100,to:offset+50}};
  }, {key:'rulebase',limit:50});
  assert.deepEqual(offsets,[0,50]);
  assert.equal(result.ok,true);
});

test('cache identity separates local/global sessions and domains', () => {
  const key = session => scopedCommandKey(session,'show-access-rulebase',{name:'Network'},JSON.stringify);
  assert.notEqual(key({sid:'local',domain:'A'}),key({sid:'global',domain:'Global'}));
  assert.notEqual(key({sid:'same',domain:'A'}),key({sid:'same',domain:'B'}));
});

test('operation guard blocks overlap until active requests drain', async () => {
  const session={};
  const operation=beginOperation(session,'scan');
  let release;
  const request=trackRequest(operation,()=>new Promise(resolve => {release=resolve;}));
  await Promise.resolve();
  operation.cancelled=true;
  assert.throws(()=>assertNotCancelled(operation), /cancelled/);
  await assert.rejects(trackRequest(operation,()=>assert.fail('new request started')), /cancelled/);
  const finished=finishOperation(session,operation);
  assert.throws(()=>beginOperation(session,'change'), /already running/);
  release();
  await request;
  await finished;
  assert.equal(session.activeOperation,null);
  const next=beginOperation(session,'check');
  await finishOperation(session,next);
});

test('shared identity merges prefixed names and retains domain/UID', () => {
  const check=withFindingIdentity({id:'gaia.allowed-host-access',status:'needs-review',evidenceTable:{rows:[
    {Name:'Gateway Name: FW1'}, {Gateway:'FW1'}
  ]}}, {domain:'domain-a',inventory:[{uid:'uid-1',name:'FW1',type:'simple-gateway'}]});
  assert.deepEqual(gatewayTargetsForCheck(check),['FW1']);
  assert.equal(check.ownership.targets[0].uid,'uid-1');
  assert.equal(check.ownership.targets[0].domain,'domain-a');
  assert.equal(check.evaluationStatus,'needs-review');
  assert.equal(checkOwnerScope({id:'updates.cpdiag'}),'management');
  assert.equal(checkOwnerScope({id:'updates.dynamic-updates'}),'management');
  assert.match(collectionMessage({collection:{status:'partial'}}),/incomplete/);
});

test('partial stealth collection never asserts an absent rule', async () => {
  const source=await readFile(new URL('../server.js',import.meta.url),'utf8');
  const start=source.indexOf('function evaluateGatewayStealthRules(');
  const end=source.indexOf('function evaluateGatewayObjectStatus(',start);
  const evaluate=vm.runInNewContext(`${source.slice(start,end)}; evaluateGatewayStealthRules`,{
    appHistory:{reviews:new Map()},makeCheck:value=>value
  });
  const check=evaluate({ok:false,gateways:[{name:'FW1'}],missingGateways:[{name:'FW1'}],
    rowsByPolicy:new Map([['Policy',[{Gateway:'FW2'}]]]),errors:[{error:'timeout'}]},{});
  assert.equal(check.status,'unknown');
  assert.match(check.evidenceTables[1].rows[0].Finding,/incomplete/);
});

test('server command adapter coalesces identical reads and paginates access rules', async () => {
  const source=await readFile(new URL('../server.js',import.meta.url),'utf8');
  const start=source.indexOf('async function tryCommand(');
  const end=source.indexOf('async function listObjects(',start);
  let calls=0;
  const run=vm.runInNewContext(`${source.slice(start,end)}; tryCommand`,{
    assertNotCancelled,operationContext:{getStore:()=>null},collectPages,scopedCommandKey,
    PAGE_LIMIT:50,SCAN_CACHEABLE_COMMANDS:new Set(['show-access-rulebase']),stableJson:JSON.stringify,
    isExpiredSessionError:()=>false,commandError:e=>({error:e.message}),
    cpRequest:async (session,command,body)=>{calls++; return {rulebase:[{uid:`r-${body.offset}`}],total:100,to:body.offset+50};}
  });
  const session={sid:'one',domain:'A',scanCommandCache:new Map()};
  const [a,b]=await Promise.all([run(session,'show-access-rulebase',{name:'Network'}),run(session,'show-access-rulebase',{name:'Network'})]);
  assert.equal(calls,2);
  assert.equal(a.data.rulebase.length,2);
  assert.equal(b.coverage.status,'complete');
  await run({...session,sid:'two'},'show-access-rulebase',{name:'Network'});
  assert.equal(calls,4);
});
