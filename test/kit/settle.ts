/** Lets everything that is already runnable run: the promise callbacks and I/O that are ready now. For "nothing has happened yet" checks. */
export const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/** Waits until `ready()` is true, checking after each turn of the event loop; fails after `timeoutMs` of real time naming `what`. */
export async function waitUntil(ready: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (!ready()) {
    if (performance.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await settle();
  }
}
