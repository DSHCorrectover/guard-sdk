/**
 * @correctover/guard-sdk v0.2.0
 * Granular access rules + Ed25519-signed audit receipts for AI agents / MCP tools.
 * Default posture: fail-closed — any action without a matching allow rule is DENIED and recorded.
 * Reuses the NB gateway fail-with-evidence kernel discipline; vectors in vectors/rule-decisions.json.
 *
 * v0.2.0 kernel upgrade (2026-11-25, absorbed from crewAI #5888 community decision-core thread
 * — ahmedmribai/agents-kit gates semantics + rpelevin/nagasatish007 decision fields):
 *  - receipt.reason_class distinguishes a measured failure from a failed measurement:
 *      "rule" (explicit rule hit) | "builtin" (built-in deny) | "fail-closed" (no rule)
 *      | "evaluator-error" (matcher threw — decision stays DENY, evidence says why).
 *      Posture note: unlike agent_toolkit.gates we do NOT offer unknown_policy="allow";
 *      authorization decisions stay fail-closed by default (see cline #15817 contrast).
 *  - rule.expires_at (epoch ms or ISO): an expired rule no longer matches => default
 *      fail-closed DENY. TTL expiry defaults to DENY (rpelevin, #5888).
 *  - rule.supersedes: explicit override chain, recorded on every receipt it influences.
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

function ruleExpired(r, nowMs = Date.now()) {
  if (r.expires_at == null) return false;
  const t = typeof r.expires_at === "number" ? r.expires_at : Date.parse(r.expires_at);
  return Number.isFinite(t) && nowMs >= t;
}

function matchRule(action, target, rules = {}, nowMs = Date.now()) {
  // ordered: explicit user rules win, then built-ins, then fail-closed default.
  // expired rules no longer match (TTL expiry => fail-closed DENY, #5888 decision-core).
  for (const r of rules.allow || []) {
    if (ruleExpired(r, nowMs)) continue;
    if (r.action === action && matchTarget(r, target)) return { decision: DECISIONS.ALLOW, rule: r.name || "custom-allow", supersedes: r.supersedes || null, reason_class: "rule" };
  }
  for (const r of rules.deny || []) {
    if (ruleExpired(r, nowMs)) continue;
    if (r.action === action && matchTarget(r, target)) return { decision: DECISIONS.DENY, rule: r.name || "custom-deny", supersedes: r.supersedes || null, reason_class: "rule" };
  }
  if (action === "env.read" && CRED_PATTERNS.some(re => re.test(target)))
    return { decision: DECISIONS.DENY, rule: "credentials-deny", supersedes: null, reason_class: "builtin" };
  if (action === "env.read")
    return { decision: DECISIONS.ALLOW, rule: "env-read-default", supersedes: null, reason_class: "builtin" };
  if ((action === "fs.write" || action === "fs.delete")) {
    if (!insideWritableRoot(target)) return { decision: DECISIONS.DENY, rule: "dev-writable", supersedes: null, reason_class: "builtin" };
    return { decision: DECISIONS.ALLOW, rule: "dev-writable", supersedes: null, reason_class: "builtin" };
  }
  if (action === "net.call" && /169\.254\.169\.254|metadata/.test(target))
    return { decision: DECISIONS.DENY, rule: "metadata-ssrf-deny", supersedes: null, reason_class: "builtin" };
  return { decision: DECISIONS.DENY, rule: "default-fail-closed", supersedes: null, reason_class: "fail-closed" };
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
    let m;
    try {
      m = matchRule(action, target, this.rules);
    } catch (e) {
      // a failed measurement is not a measured failure: the decision stays DENY
      // (fail-closed posture unchanged) but the receipt records the evaluator fault.
      m = { decision: DECISIONS.DENY, rule: "evaluator-error", supersedes: null, reason_class: "evaluator-error", error: String(e && e.message || e) };
    }
    return this.issueReceipt({ action, target, decision: m.decision, rule: m.rule, reason_class: m.reason_class, supersedes: m.supersedes ?? null });
  }

  issueReceipt(claim) {
    const body = JSON.stringify({ ...claim, ts: new Date().toISOString(), issuer: "correctover-guard", v: "0.2.0" });
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
