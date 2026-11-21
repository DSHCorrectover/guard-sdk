/**
 * @correctover/guard-sdk v0.1.0
 * Granular access rules + Ed25519-signed audit receipts for AI agents / MCP tools.
 * Default posture: fail-closed — any action without a matching allow rule is DENIED and recorded.
 * Reuses the NB gateway fail-with-evidence kernel discipline; vectors in vectors/rule-decisions.json.
 */
import { createPrivateKey, createPublicKey, sign, verify, generateKeyPairSync } from "node:crypto";

export const DECISIONS = { ALLOW: "ALLOW", DENY: "DENY" };
const CRED_PATTERNS = [/SECRET/i, /TOKEN/i, /PASS(WORD)?/i, /API_?KEY/i, /^\.env$/];

/** Normalize a path and test it stays inside the allowed writable root. */
function insideWritableRoot(p, root = "src/") {
  const norm = String(p).replace(/\\/g, "/").replace(/\/+/g, "/");
  // resolve .. segments without fs
  const parts = [];
  for (const seg of norm.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg !== ".") parts.push(seg);
  }
  const resolved = parts.join("/");
  return resolved.startsWith(root) && resolved.length > root.length;
}

function matchRule(action, target, rules = {}) {
  // ordered: explicit user rules win, then built-ins, then fail-closed default
  for (const r of rules.allow || []) {
    if (r.action === action && matchTarget(r, target)) return { decision: DECISIONS.ALLOW, rule: r.name || "custom-allow" };
  }
  for (const r of rules.deny || []) {
    if (r.action === action && matchTarget(r, target)) return { decision: DECISIONS.DENY, rule: r.name || "custom-deny" };
  }
  if (action === "env.read" && CRED_PATTERNS.some(re => re.test(target)))
    return { decision: DECISIONS.DENY, rule: "credentials-deny" };
  if (action === "env.read")
    return { decision: DECISIONS.ALLOW, rule: "env-read-default" };
  if ((action === "fs.write" || action === "fs.delete")) {
    if (!insideWritableRoot(target)) return { decision: DECISIONS.DENY, rule: "dev-writable" };
    return { decision: DECISIONS.ALLOW, rule: "dev-writable" };
  }
  if (action === "net.call" && /169\.254\.169\.254|metadata/.test(target))
    return { decision: DECISIONS.DENY, rule: "metadata-ssrf-deny" };
  return { decision: DECISIONS.DENY, rule: "default-fail-closed" };
}

function matchTarget(r, target) {
  if (r.match instanceof RegExp) return r.match.test(target);
  if (typeof r.match === "string") return target === r.match || target.startsWith(r.match);
  return true;
}

export class Guard {
  /**
   * @param {object} opts
   * @param {object} [opts.rules]  { allow: [{action, match, name}], deny: [...] }
   * @param {Buffer} [opts.privateKey] PEM Ed25519 private key; generated if omitted
   */
  constructor(opts = {}) {
    this.rules = opts.rules || {};
    if (opts.privateKey) {
      this._priv = createPrivateKey(opts.privateKey);
    } else {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      this._priv = privateKey;
      this.publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    }
    this.publicKeyPem ||= createPublicKey(this._priv).export({ type: "spki", format: "pem" });
  }

  /** Evaluate an action; returns the decision AND a signed receipt (evidence of what was decided and why). */
  evaluate(action, target) {
    const { decision, rule } = matchRule(action, target, this.rules);
    return this.issueReceipt({ action, target, decision, rule });
  }

  issueReceipt(claim) {
    const body = JSON.stringify({ ...claim, ts: new Date().toISOString(), issuer: "correctover-guard", v: "0.1.0" });
    const sig = sign(null, Buffer.from(body), this._priv).toString("base64");
    return { ...claim, receipt: { body, signature: sig, alg: "Ed25519" } };
  }

  /** Verify a receipt against this guard's public key — the audit path. */
  static verifyReceipt(receipt, publicKeyPem) {
    try {
      const ok = verify(null, Buffer.from(receipt.body), createPublicKey(publicKeyPem), Buffer.from(receipt.signature, "base64"));
      return { valid: ok, claim: ok ? JSON.parse(receipt.body) : null };
    } catch (e) {
      return { valid: false, claim: null, reason: String(e.message) };
    }
  }
}

export default Guard;
