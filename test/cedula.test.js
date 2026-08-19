import { test } from "node:test";
import { execFile } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const BIN = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "cedula.js");

function cfg(obj) {
  const f = join(mkdtempSync(join(tmpdir(), "cedula-")), "config.json");
  writeFileSync(f, JSON.stringify(obj));
  return f;
}

test("trace: keychain source", async () => {
  const f = cfg({ providers: { azure: { apiKey: "!security find-generic-password -s 'ai.azure.x' -w" } } });
  const { stdout } = await run("node", [BIN, "trace", f, "providers.azure.apiKey"]);
  if (!/keychain/.test(stdout)) throw new Error("expected keychain: " + stdout);
  if (/supersecret/i.test(stdout)) throw new Error("must not print secrets");
});

test("trace: pi auth store source", async () => {
  const f = cfg({ a: { k: "!pi auth print-api-key --provider amazon-bedrock" } });
  const { stdout } = await run("node", [BIN, "trace", f, "a.k"]);
  if (!/auth-store/.test(stdout)) throw new Error("expected auth-store: " + stdout);
});

test("trace: literal flagged", async () => {
  const f = cfg({ a: { k: "plain-inline-value" } });
  const { stdout } = await run("node", [BIN, "trace", f, "a.k"]);
  if (!/literal/.test(stdout)) throw new Error("expected literal: " + stdout);
});

test("trace: missing key exits 1", async () => {
  const f = cfg({ a: {} });
  await run("node", [BIN, "trace", f, "a.nope"]).then(
    () => { throw new Error("should have failed"); },
    (e) => { if (e.code !== 1) throw e; },
  );
});

test("scan: finds all externalized values", async () => {
  const f = cfg({
    x: { key: "!security find-generic-password -s s -w" },
    y: { key: "!op read op://v/i/f" },
    z: { plain: "inline" },
  });
  const { stdout } = await run("node", [BIN, "scan", f]);
  if (!/x\.key/.test(stdout) || !/y\.key/.test(stdout)) throw new Error("missing keys: " + stdout);
  if (/z\.plain/.test(stdout)) throw new Error("should not list plain values");
});
