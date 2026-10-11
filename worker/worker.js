/**
 * おうちトーク 通知中継（Cloudflare Worker）
 *
 * 役割：家族のだれかがメッセージを送ったら、ほかの家族のスマホに
 *       Web Push（アプリを閉じていても届く通知）を送る。
 *
 * 必要な設定（Cloudflareの管理画面で行う）
 *   - KV ネームスペースを作り、変数名 SUBS で紐づける
 *   - 環境変数 ALLOWED_ORIGIN = おうちトークを公開したサイトの元URL
 *       例）https://yourname.github.io   （末尾の / やフォルダ名は不要）
 *
 * このプログラムが受け取るもの
 *   - 家族の目印（合言葉から作った別の値。合言葉そのものではない）
 *   - 各スマホの通知の宛先（ブラウザが発行するもの）
 *   - 通知の中身（家族の合言葉で暗号化済み。このプログラムには読めない）
 *
 * 窓口
 *   GET  /vapid        通知用の公開鍵を返す（初回アクセス時に自動で鍵を作る）
 *   POST /subscribe    {room, dev, sub}  この端末に通知を届けるよう登録
 *   POST /unsubscribe  {room, endpoint}  登録を解除
 *   POST /notify       {room, dev, p}    送信者以外の家族に通知を送る
 */

const MAX_SUBS_PER_ROOM = 30;
const MAX_PAYLOAD_CHARS = 2800; // Web Pushの上限(約4KB)に収まる大きさ
const TTL_SECONDS = 60 * 60 * 24; // 電源が切れていても1日以内に届けば配達

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (!cors["Access-Control-Allow-Origin"]) return json({ error: "origin_not_allowed" }, 403, cors);

    const path = new URL(req.url).pathname.replace(/\/+$/, "");
    try {
      if (req.method === "GET" && path === "/vapid") {
        const v = await getVapid(env);
        return json({ key: v.publicKey }, 200, cors);
      }
      if (req.method !== "POST") return json({ error: "not_found" }, 404, cors);

      const body = await req.json().catch(() => null);
      if (!body || !isRoom(body.room)) return json({ error: "bad_request" }, 400, cors);

      if (path === "/subscribe") return json(await subscribe(env, body), 200, cors);
      if (path === "/unsubscribe") return json(await unsubscribe(env, body), 200, cors);
      if (path === "/notify") return json(await notify(env, body), 200, cors);
      return json({ error: "not_found" }, 404, cors);
    } catch (e) {
      return json({ error: "server_error", detail: String(e && e.message || e) }, 500, cors);
    }
  }
};

/* ---------- 窓口ごとの処理 ---------- */

async function subscribe(env, { room, dev, sub }) {
  if (!sub || typeof sub.endpoint !== "string" || !sub.keys || !sub.keys.p256dh || !sub.keys.auth)
    throw new Error("subscription_missing");
  const u = new URL(sub.endpoint);
  if (u.protocol !== "https:") throw new Error("bad_endpoint");
  const list = await loadRoom(env, room);
  const rest = list.filter(s => s.endpoint !== sub.endpoint && s.dev !== String(dev || ""));
  rest.push({ endpoint: sub.endpoint, p256dh: sub.keys.p256dh, auth: sub.keys.auth, dev: String(dev || "").slice(0, 32), at: Date.now() });
  while (rest.length > MAX_SUBS_PER_ROOM) rest.shift();
  await env.SUBS.put("room:" + room, JSON.stringify(rest));
  return { ok: true, devices: rest.length };
}

async function unsubscribe(env, { room, endpoint }) {
  const list = await loadRoom(env, room);
  const rest = list.filter(s => s.endpoint !== endpoint);
  if (rest.length !== list.length) await env.SUBS.put("room:" + room, JSON.stringify(rest));
  return { ok: true };
}

async function notify(env, { room, dev, p }) {
  if (typeof p !== "string" || p.length > MAX_PAYLOAD_CHARS) throw new Error("payload_invalid");
  const list = await loadRoom(env, room);
  const targets = list.filter(s => s.dev !== String(dev || ""));
  if (!targets.length) return { ok: true, sent: 0 };

  const vapid = await getVapid(env);
  const payload = new TextEncoder().encode(JSON.stringify({ v: 1, p }));
  const gone = [];
  let sent = 0;
  await Promise.all(targets.map(async s => {
    try {
      const res = await sendPush(s, payload, vapid, env);
      if (res.status === 404 || res.status === 410) gone.push(s.endpoint); // スマホ側で通知をやめた
      else if (res.ok) sent++;
    } catch { /* 1台の失敗で全体を止めない */ }
  }));
  if (gone.length) {
    const rest = list.filter(s => !gone.includes(s.endpoint));
    await env.SUBS.put("room:" + room, JSON.stringify(rest));
  }
  return { ok: true, sent, removed: gone.length };
}

/* ---------- 保存 ---------- */

function isRoom(r) { return typeof r === "string" && /^[0-9a-f]{32}$/.test(r); }

async function loadRoom(env, room) {
  const raw = await env.SUBS.get("room:" + room);
  try { const a = JSON.parse(raw || "[]"); return Array.isArray(a) ? a : []; } catch { return []; }
}

// 通知用の鍵（VAPID）。初回だけ作ってKVに保存し、以後は同じものを使う。
let vapidCache = null;
async function getVapid(env) {
  if (vapidCache) return vapidCache;
  let stored = await env.SUBS.get("vapid", "json");
  if (!stored) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    stored = { jwk, publicKey: b64u(pub) };
    await env.SUBS.put("vapid", JSON.stringify(stored));
  }
  const key = await crypto.subtle.importKey("jwk", stored.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  vapidCache = { key, publicKey: stored.publicKey };
  return vapidCache;
}

/* ---------- Web Push 本体（RFC 8291 暗号化 + RFC 8292 VAPID署名） ---------- */

async function sendPush(sub, payload, vapid, env) {
  const body = await encryptPayload(payload, b64uDecode(sub.p256dh), b64uDecode(sub.auth));
  const aud = new URL(sub.endpoint).origin;
  const jwt = await vapidJwt(aud, vapid.key, subject(env));
  return fetch(sub.endpoint, {
    method: "POST",
    headers: {
      "Authorization": `vapid t=${jwt}, k=${vapid.publicKey}`,
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "TTL": String(TTL_SECONDS),
      "Urgency": "high"
    },
    body
  });
}

function subject(env) {
  const o = String(env.ALLOWED_ORIGIN || "").split(",")[0].trim();
  return o.startsWith("https://") ? o : "https://example.invalid";
}

async function vapidJwt(aud, key, sub) {
  const enc = new TextEncoder();
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub })));
  const data = `${head}.${claims}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(data)));
  return `${data}.${b64u(sig)}`;
}

async function encryptPayload(plain, uaPublic, authSecret) {
  const enc = new TextEncoder();
  // 送るたびに使い捨ての鍵を作る
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, as.privateKey, 256));

  const keyInfo = concat(enc.encode("WebPush: info\0"), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, shared, keyInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const padded = concat(plain, new Uint8Array([2])); // 最後のレコードの印
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, padded));

  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return concat(header, ct);
}

async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}

/* ---------- 小道具 ---------- */

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = String(env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim().replace(/\/+$/, "")).filter(Boolean);
  const h = { "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "86400", "Vary": "Origin" };
  if (allowed.includes(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}
function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status, headers: { ...headers, "Content-Type": "application/json; charset=utf-8" } });
}
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function b64u(u8) {
  let s = ""; for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
