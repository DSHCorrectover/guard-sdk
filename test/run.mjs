/* Guard SDK test: vector-locked decisions + end-to-end receipt signing. ALL must PASS. */
import { readFileSync } from "node:fs";
import { Guard } from "../src/index.mjs";

const vectors = JSON.parse(readFileSync(new URL("../vectors/rule-decisions.json", import.meta.url), "utf8"));
const guard = new Guard();

let pass = 0, fail = 0;
const t = (name, ok, extra = "") => { console.log((ok ? "PASS" : "FAIL") + "  " + name + (ok ? "" : "  " + extra)); ok ? pass++ : fail++; };

// 1) rule-decision vectors (locked; add a new vector => test count changes => CI catches silent edits)
t("vector count matches suite (13)", vectors.vectors.length === 13, String(vectors.vectors.length));

// v0.2 guards for the new vector classes (crewAI #5888 decision-core absorption)
const ttlGuard = new Guard({ rules: { allow: [
  { action: "mcp.tool", match: "anything", name: "expired-window", expires_at: "2020-01-01T00:00:00Z", supersedes: "legacy-open" }
]}});
const liveGuard = new Guard({ rules: { allow: [
  { action: "env.read", match: "DEMO_VAR", name: "rotating-window", expires_at: "2099-01-01T00:00:00Z", supersedes: "legacy-open" }
]}});

for (const v of vectors.vectors) {
  let r;
  if (v.id === "rd-11") r = ttlGuard.evaluate(v.action, v.target);
  else if (v.id === "rd-12") r = liveGuard.evaluate(v.action, v.target);
  else r = guard.evaluate(v.action, v.target);
  t(`rd ${v.id} ${v.action} ${v.target} => ${v.expect}`, r.decision === v.expect, `got ${r.decision} rule=${r.rule}`);
  // every decision must carry a signed receipt
  t(`rd ${v.id} receipt attached`, !!r.receipt?.signature);
}

// 2) v0.2 kernel semantics
// reason_class: fail-closed deny says so (measured failure vs failed measurement)
const fc = guard.evaluate("mcp.tool", "anything_unmatched");
t("fail-closed reason_class", fc.reason_class === "fail-closed", String(fc.reason_class));
const builtin = guard.evaluate("env.read", "AWS_SECRET_ACCESS_KEY");
t("builtin deny reason_class", builtin.reason_class === "builtin" && builtin.decision === "DENY", String(builtin.reason_class));
const ruleHit = liveGuard.evaluate("env.read", "DEMO_VAR");
t("rule-hit reason_class + supersedes recorded", ruleHit.reason_class === "rule" && ruleHit.supersedes === "legacy-open", JSON.stringify({ rc: ruleHit.reason_class, sup: ruleHit.supersedes }));
// TTL expiry: expired rule stops matching => default fail-closed DENY
const ttl = ttlGuard.evaluate("mcp.tool", "expired-ttl-target");
t("expired rule => fail-closed DENY (TTL defaults to deny)", ttl.decision === "DENY" && ttl.reason_class === "fail-closed", `${ttl.decision} ${ttl.reason_class}`);
// evaluator-error: a failed measurement is still DENY but evidence says why
const errGuard = new Guard();
errGuard.rules.allow = [{ get action() { throw new Error("boom-in-matcher"); }, match: "x", name: "poison" }];
const ee = errGuard.evaluate("env.read", "SAFE_VAR");
t("evaluator-error => DENY stays + reason_class records fault", ee.decision === "DENY" && ee.reason_class === "evaluator-error", `${ee.decision} ${ee.reason_class}`);

// 2) receipt end-to-end: verify genuine + detect tampering
const r = guard.evaluate("fs.write", "src/hello.ts");
const g1 = Guard.verifyReceipt(r.receipt, guard.publicKeyPem);
t("receipt verifies (genuine)", g1.valid === true && g1.claim.decision === "ALLOW");

const tampered = JSON.parse(JSON.stringify(r.receipt));
tampered.body = tampered.body.replace('"ALLOW"', '"DENY"');
const g2 = Guard.verifyReceipt(tampered, guard.publicKeyPem);
t("receipt rejects (tampered body)", g2.valid === false);

// 3) fail-closed sanity: unknown action is denied, not allowed
const u = guard.evaluate("mcp.tool", "anything__dangerous");
t("unknown mcp tool fail-closed DENY", u.decision === "DENY" && u.rule === "default-fail-closed");

console.log(`\n${pass} PASS / ${fail} FAIL`);
process.exit(fail ? 1 : 0);
