/* おうちトーク Service Worker
 * アプリを閉じていても届く通知（Web Push）を受け取って表示する。
 * 通知の中身は家族の合言葉で暗号化されているので、端末に保存した鍵で開く。
 */
const APP = "ouchi-talk-v1";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

/* ---- 端末内の保存場所（ページと共有） ---- */
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("ouchi-talk", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const q = db.transaction("kv").objectStore("kv").get(k);
    q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
  });
}

async function openSealed(key, s) {
  const u = Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.subarray(0, 12) }, key, u.subarray(12));
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---- 通知を受け取ったとき ---- */
self.addEventListener("push", e => e.waitUntil(onPush(e)));

async function onPush(e) {
  let title = "おうちトーク", body = "新しいメッセージがあります";
  try {
    const outer = e.data ? e.data.json() : null;
    const conf = await idbGet("push");
    if (outer && outer.p && conf && conf.key) {
      const m = await openSealed(conf.key, outer.p);
      if (m && m.app === APP) {
        title = String(m.n || "家族").slice(0, 16);
        body = m.t === "img" ? "写真が届きました"
             : m.t === "stamp" ? String(m.b || "スタンプ")
             : String(m.b || "").slice(0, 100);
      }
    }
  } catch { /* 開けなくても「新着あり」だけは知らせる */ }

  // アプリを見ている最中なら、音を鳴らさずすぐ消す（iPhoneは通知の表示が必須のため）
  const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const watching = wins.some(c => c.visibilityState === "visible");

  await self.registration.showNotification(title, {
    body,
    tag: "ouchi-talk",
    renotify: !watching,
    silent: watching,
    icon: "icon-192.png",
    data: { url: self.registration.scope }
  });
  if (watching) {
    const ns = await self.registration.getNotifications({ tag: "ouchi-talk" });
    ns.forEach(n => n.close());
  }
  try { if (!watching && self.navigator.setAppBadge) await self.navigator.setAppBadge(); } catch {}
}

/* ---- 通知をタップしたとき ---- */
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || self.registration.scope;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of wins) {
      if (c.url.startsWith(self.registration.scope) && "focus" in c) return c.focus();
    }
    return self.clients.openWindow(url);
  })());
});

/* ---- 通知の宛先が自動で更新されたとき ---- */
self.addEventListener("pushsubscriptionchange", e => {
  e.waitUntil((async () => {
    const conf = await idbGet("push");
    if (!conf || !conf.url || !conf.vapid) return;
    const sub = await self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: conf.vapid
    });
    await fetch(conf.url + "/subscribe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room: conf.room, dev: conf.dev, sub: sub.toJSON() })
    });
  })());
});
