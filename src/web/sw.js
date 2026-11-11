// The service worker (KBOX-22): shows the box's one-line title, sets the badge to the number waiting, and opens the app at
// the box's own origin when tapped. A payload carries title, kind and count only, never a link.

/**
 * @typedef {{ data: { json(): unknown } | null, waitUntil(p: Promise<unknown>): void }} PushEvent
 * @typedef {{ notification: { close(): void }, waitUntil(p: Promise<unknown>): void }} ClickEvent
 * @typedef {{ registration: { showNotification(title: string, o: { tag: string }): Promise<void> },
 *   navigator: { setAppBadge?: (n?: number) => Promise<void> },
 *   clients: { openWindow(url: string): Promise<unknown> },
 *   addEventListener(type: 'push', l: (e: PushEvent) => void): void }} Worker
 */
const worker = /** @type {Worker} */ (/** @type {unknown} */ (globalThis));
const clickable = /** @type {{ addEventListener(type: 'notificationclick', l: (e: ClickEvent) => void): void }} */ (/** @type {unknown} */ (globalThis));

worker.addEventListener('push', (event) => {
  const body = /** @type {{ title?: unknown, count?: unknown }} */ (event.data?.json() ?? {});
  const title = typeof body.title === 'string' ? body.title : 'Something waits on the key box';
  const badge = typeof body.count === 'number' ? worker.navigator.setAppBadge?.(body.count) : worker.navigator.setAppBadge?.();
  event.waitUntil(Promise.all([worker.registration.showNotification(title, { tag: 'keybox' }), badge]));
});

clickable.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(worker.clients.openWindow('/'));
});
