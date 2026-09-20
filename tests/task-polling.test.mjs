import test from 'node:test';
import assert from 'node:assert/strict';
import {pollScriptTasks, scriptTaskState} from '../lib/task-polling.js';

function fixture(request, extra = {}) {
  let clock = 0;
  return pollScriptTasks({initial: {ok:true,data:{}}, taskIds:['a'], targets:['LAB'],
    now:()=>clock, sleep:async ms=>{clock+=ms;}, request:id=>request(id,clock), ...extra});
}
const response = (id, status, details = {}) => ({ok:true,data:{tasks:[{'task-id':id,status,'task-details':[details]}]}});

test('waits beyond 20 seconds and ignores progress descriptions and partial output', async () => {
  let calls=0;
  const result=await fixture((id,time)=>{calls++;return response(id,time<65000?'in progress':'succeeded', {statusDescription:'Running commands',responseMessage:'cGFydGlhbA=='});});
  assert.equal(result.ok,true);assert(calls>16);assert.equal(result.data.tasks[0].status,'succeeded');
});
test('waits for all task IDs, retaining early completed results', async () => {
  const calls={a:0,b:0};
  const result=await fixture((id,time)=>{calls[id]++;return response(id,id==='a'||time>9000?'succeeded':'in progress');},{taskIds:['a','b']});
  assert.equal(result.ok,true);assert.equal(result.data.tasks.length,2);assert.equal(calls.a,1);assert(calls.b>1);
});
test('HTTP success cannot hide a task or target failure', async () => {
  const result=await fixture(id=>response(id,'succeeded',{statusCode:'failed',statusDescription:'Permission denied'}));
  assert.equal(result.ok,false);assert.match(result.error.error,/LAB/);assert.equal(result.error.tasks[0]['task-details'][0].statusDescription,'Permission denied');
});
test('deadline returns explicit timeout instead of an HTTP-success result', async () => {
  const result=await fixture(id=>response(id,'in progress',{statusDescription:'Still running'}),{timeoutMs:10000});
  assert.equal(result.ok,false);assert.equal(result.error.code,'SCRIPT_TASK_TIMEOUT');assert.deepEqual(result.error.taskIds,['a']);assert.match(result.error.error,/no script was resubmitted/);
});
test('transient poll failure is retried, not a second script submission', async () => {
  let calls=0;const result=await fixture(id=>++calls===1?{ok:false,error:{error:'network'}}:response(id,'succeeded'));
  assert.equal(result.ok,true);assert.equal(calls,2);
});
test('cancellation interrupts polling', async () => {
  let checks=0;await assert.rejects(fixture(id=>response(id,'in progress'),{checkCancelled:()=>{if(++checks>2)throw Error('cancelled');}}),/cancelled/);
});
test('unknown statuses and partial success are not successful completion', () => {
  assert.equal(scriptTaskState({status:'unknown'}),'pending');
  assert.equal(scriptTaskState({status:'partially succeeded'}),'failed');
  assert.equal(scriptTaskState({status:'succeeded'}),'succeeded');
});
