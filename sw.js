// Blind Vote service worker: shows the "Results are in" notification and opens the poll when it's tapped.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("push", e => {
  let d = {};
  try { d = e.data.json(); } catch (err) {}
  e.waitUntil(self.registration.showNotification(d.title || "Blind Vote", {
    body: d.body || "A poll has closed. Tap to see the results.",
    icon: "icon-192.png", badge: "icon-192.png", tag: d.poll || "blind-vote",
    data: { url: self.registration.scope + (d.poll ? "?p=" + d.poll : "") },
  }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(self.clients.openWindow(e.notification.data.url));
});
