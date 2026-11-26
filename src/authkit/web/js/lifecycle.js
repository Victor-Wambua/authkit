// Views register timers and listeners here; the router runs them before the next render.
const cleanups = [];
export function onCleanup(fn) { cleanups.push(fn); }
export function runCleanups() { while (cleanups.length) { try { cleanups.pop()(); } catch { /* ignore */ } } }
