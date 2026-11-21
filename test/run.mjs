/* Guard SDK test: vector-locked decisions + end-to-end receipt signing. ALL must PASS. */
import { readFileSync } from "node:fs";
import { Guard } from "../src/index.mjs";

const vectors = JSON.parse(readFileSync(new URL("../vectors/rule-decisions.json", import.meta.url), "utf8"));
const guard = new Guard();

let pass = 0, fail = 0;
const t = (name, ok, extra = "") => { console.log((ok ? "PASS" : "FAIL") + "  " + name + (ok ? "" : "  " + extra)); ok ? pass++ : fail++; };

// 1) rule-decision vectors (locked; add a new vector => test count changes => CI catches silent edits)
t("vector count matches suite (10)", vectors.vectors.length === 10, String(vectors.vectors.length));

for (const v of vectors.vectors) {
  const r = guard.evaluate(v.action, v.target);
  t(`rd ${v.id} ${v.action} ${v.target} => ${v.expect}`, r.decision === v.expect, `got ${r.decision} rule=${r.rule}`);
  // every decision must carry a signed receipt
  t(`rd ${v.id} receipt attached`, !!r.receipt?.signature);
}

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
