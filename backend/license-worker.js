/**
 * Guard SDK License Worker (Cloudflare Workers, 无依赖)
 * 部署: wrangler deploy ｜ 密钥经 wrangler secret put GUARD_SIGNING_KEY
 * 流程: Stripe/LS Webhook -> /issue 生成 Ed25519 license -> 客户本地 SDK 校验
 * 铁律: 密钥只进 Workers Secrets, 永不入库/日志/回显
 */
const enc = new TextEncoder();
const KEY_ALG = { name: "Ed25519" };

async function getKey(env, format) {
  const raw = base64Decode(env.GUARD_SIGNING_KEY);
  return format === "priv"
    ? crypto.subtle.importKey("pkcs8", pkcs8Wrap(raw), KEY_ALG, false, ["sign"])
    : crypto.subtle.importKey("raw", raw.pub || raw, KEY_ALG, false, ["verify"]);
}
// 极简 pkcs8 前缀 (Ed25519 RFC 8410)
const PKCS8_PREFIX = new Uint8Array([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
const pkcs8Wrap = seed => { const out = new Uint8Array(48); out.set(PKCS8_PREFIX); out.set(seed, 16); return out; };
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const base64Decode = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/issue" && req.method === "POST") {
      const b = await req.json();
      const lic = { plan: b.plan, email: b.email, seats: b.seats||1, ops: b.ops||1000,
        exp: Date.now() + 30*864e5, iat: Date.now(), issuer: "correctover-guard" };
      const payload = btoa(JSON.stringify(lic)).replace(/=+$/,"");
      const key = await getKey(env, "priv");
      const sig = b64(await crypto.subtle.sign(KEY_ALG, key, enc.encode(payload)));
      return Response.json({ license: `${payload}.${sig.replace(/=+$/,"")}`, plan: lic.plan, exp: lic.exp });
    }
    if (url.pathname === "/verify" && req.method === "POST") {
      const { license } = await req.json();
      const [payload, sig] = license.split(".");
      const ok = await crypto.subtle.verify(KEY_ALG, await getKey(env, "pub"),
        base64Decode(sig + "=".repeat((4 - sig.length % 4) % 4)), enc.encode(payload));
      const data = JSON.parse(atob(payload));
      const valid = ok && data.exp > Date.now();
      return Response.json({ valid, plan: data.plan, exp: data.exp, reason: valid ? null : (ok ? "expired" : "bad-signature") });
    }
    return new Response("correctover-guard license worker", { status: 200 });
  }
};
