import { AsyncLocalStorage } from 'node:async_hooks';

export const operationContext = new AsyncLocalStorage();
export function beginOperation(session, kind) {
  if (session.activeOperation) throw Object.assign(new Error(`A ${session.activeOperation.kind} operation is already running.`), { httpStatus: 409 });
  const operation = { kind, cancelled: false, pending: new Set() };
  session.activeOperation = operation;
  return operation;
}
export function assertNotCancelled(operation) {
  if (operation?.cancelled) throw Object.assign(new Error('Scan cancelled. Previously completed results remain available.'), { code: 'SCAN_CANCELLED', httpStatus: 409 });
}
export async function finishOperation(session, operation) {
  operation.cancelled = true;
  // Promise.all can reject while sibling collectors are still running.
  while (operation.pending.size) await Promise.allSettled([...operation.pending]);
  if (session.activeOperation === operation) session.activeOperation = null;
}
export function trackRequest(operation, execute) {
  const pending = Promise.resolve().then(() => { assertNotCancelled(operation); return execute(); });
  if (operation) {
    operation.pending.add(pending);
    pending.then(() => operation.pending.delete(pending), () => operation.pending.delete(pending));
  }
  return pending;
}
