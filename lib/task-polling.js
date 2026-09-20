// A successful HTTP request is not a completed asynchronous script.
export function scriptTaskState(task) {
  const normalize = value => String(value || '').trim().toLowerCase().replaceAll('_', ' ');
  const details = task?.['task-details'] || task?.taskDetails || [];
  const items = Array.isArray(details) ? details : [details];
  const states = [task?.status, ...items.map(item => item?.statusCode || item?.status)]
    .map(normalize).filter(Boolean);
  if (states.some(state => ['failed', 'failure', 'partially succeeded', 'cancelled', 'canceled'].includes(state))) return 'failed';
  if (normalize(task?.status) === 'succeeded' && states.every(state => state === 'succeeded')) return 'succeeded';
  return 'pending';
}

export async function pollScriptTasks({initial, taskIds, request, timeoutMs = 180_000,
  intervalMs = 1000, maxIntervalMs = 4000, sleep, now = Date.now, checkCancelled = () => {}, targets = []}) {
  const started = now();
  const completed = new Map();
  const lastStates = new Map();
  let lastError;
  let attempt = 0;
  while (now() - started < timeoutMs) {
    checkCancelled();
    await sleep(Math.min(intervalMs * ++attempt, maxIntervalMs, timeoutMs - (now() - started)));
    checkCancelled();
    if (now() - started >= timeoutMs) break;
    await Promise.all(taskIds.filter(id => !completed.has(id)).map(async id => {
      const result = await request(id);
      checkCancelled();
      if (!result.ok) { lastError = result.error; lastStates.set(id, 'poll request failed'); return; }
      const tasks = result.data?.tasks || [];
      const task = tasks.find(item => (item['task-id'] || item.taskId || item.uid) === id)
        || (tasks.length === 1 && !tasks[0]['task-id'] && !tasks[0].taskId && !tasks[0].uid ? tasks[0] : null);
      if (!task) { lastStates.set(id, 'task not returned'); return; }
      const state = scriptTaskState(task);
      lastStates.set(id, task.status || state);
      if (state !== 'pending') completed.set(id, task);
    }));
    if (completed.size === taskIds.length) {
      const tasks = taskIds.map(id => completed.get(id));
      const failed = tasks.filter(task => scriptTaskState(task) === 'failed');
      if (!failed.length) return {...initial, ok: true, data: {...initial.data, tasks}};
      return {ok: false, data: {tasks}, error: {error: `run-script failed for ${targets.join(', ') || 'target'}; task IDs: ${taskIds.join(', ')}`, tasks: failed}};
    }
  }
  return {ok: false, error: {
    error: `Timed out waiting ${Math.round(timeoutMs / 1000)} seconds for run-script completion on ${targets.join(', ') || 'target'}. The task may still be running; no script was resubmitted.`,
    code: 'SCRIPT_TASK_TIMEOUT', taskIds, targets, lastStates: Object.fromEntries(lastStates),
    ...(lastError ? {lastPollError: lastError} : {})
  }};
}
