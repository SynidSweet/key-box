/** Lets everything that is already runnable run: the promise callbacks and I/O that are ready now. For "nothing has happened yet" checks. */
export const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
