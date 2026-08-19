#!/usr/bin/env node
/**
 * cédula — credential & config provenance tracer.
 *
 * Answers "where does this value actually come from?" without ever printing
 * the secret. Given a config file (JSON) and a key path, it resolves the
 * provenance chain: literal value, env var, or command substitution, and
 * reports the *source* — never the resolved secret.
 *
 *   cedula trace <file> <keypath>     trace one value's provenance
 *   cedula scan <file>                list every command-substituted key
 *
 * Exit 0 always; this is a read-only inspection tool.
 */
import { readFileSync } from "node:fs";

const SHELL_SOURCE_RE = /^!(.+)$/;

function red() { return process.stdout.isTTY ? "\x1b[31m" : ""; }
function mint() { return process.stdout.isTTY ? "\x1b[32m" : ""; }
function dim() { return process.stdout.isTTY ? "\x1b[2m" : ""; }
function rst() { return process.stdout.isTTY ? "\x1b[0m" : ""; }

/** Get a value by dotted key path: "providers.azure.apiKey". */
function getPath(obj, path) {
  return path.split(".").reduce((o, k) => (o == null ? o : o[k]), obj);
}

/**
 * Classify a leaf value's provenance. Never returns the resolved secret, and
 * never carries the raw command — only an allowlisted, non-secret identifier
 * (e.g. a Keychain service name) plus the executable's name.
 */
function classify(value) {
  if (typeof value !== "string") return { kind: "literal", detail: typeof value };
  const m = value.match(SHELL_SOURCE_RE);
  if (!m) return { kind: "literal", detail: "inline string (consider externalizing)" };
  const cmd = m[1];
  // Extract only the leading executable name — never the full command, which
  // could carry an inline token or sensitive argument.
  const exe = (cmd.trim().match(/^[^\s]+/) || ["command"])[0].replace(/^.*\//, "");
  if (/\bsecurity\s+find-generic-password\b/.test(cmd)) {
    const svc = cmd.match(/-s\s+'?([^'\s]+)'?/);
    return { kind: "keychain", detail: `macOS Keychain${svc ? ` (service "${svc[1]}")` : ""}`, via: exe };
  }
  if (/\bpi\s+auth\s+print-api-key\b/.test(cmd)) {
    const prov = cmd.match(/--provider\s+'?([^'\s]+)'?/);
    return { kind: "auth-store", detail: `pi auth store${prov ? ` (provider "${prov[1]}")` : ""}`, via: exe };
  }
  if (/\bop\s+read\b|\bop\s+item\s+get\b/.test(cmd)) return { kind: "1password", detail: "1Password CLI", via: exe };
  if (/\baws\b/.test(cmd)) return { kind: "aws", detail: "AWS CLI / SSO", via: exe };
  return { kind: "command", detail: "shell command substitution", via: exe };
}

function trace(file, keypath) {
  const config = JSON.parse(readFileSync(file, "utf8"));
  const value = getPath(config, keypath);
  if (value === undefined) {
    console.error(`${red()}✗${rst()} key not found: ${keypath}`);
    process.exitCode = 1;
    return;
  }
  const c = classify(value);
  console.log(`${mint()}${keypath}${rst()}`);
  console.log(`  source:   ${c.kind}`);
  console.log(`  ${dim()}${c.detail}${rst()}`);
  if (c.via) console.log(`  via:      ${dim()}${c.via} (command shape withheld — may carry a secret)${rst()}`);
  console.log(`  resolved: ${dim()}(never printed — secret stays in the store)${rst()}`);
}

/** Walk an object, yielding [path, value] for every string leaf with `!`. */
function* walk(obj, prefix = []) {
  for (const [k, v] of Object.entries(obj ?? {})) {
    const path = [...prefix, k];
    if (typeof v === "string" && SHELL_SOURCE_RE.test(v)) yield [path.join("."), v];
    else if (v && typeof v === "object") yield* walk(v, path);
  }
}

function scan(file) {
  const config = JSON.parse(readFileSync(file, "utf8"));
  const found = [...walk(config)];
  if (!found.length) {
    console.log(`${mint()}✓${rst()} no command-substituted values in ${file}`);
    return;
  }
  console.log(`${found.length} externalized value(s) in ${file}:\n`);
  for (const [path, value] of found) {
    const c = classify(value);
    console.log(`  ${mint()}${path}${rst()}`);
    console.log(`    → ${c.kind}: ${dim()}${c.detail}${rst()}`);
  }
  console.log(`\n${dim()}secrets resolved at runtime; none printed here.${rst()}`);
}

const [, , cmd, file, keypath] = process.argv;
if (!file || (cmd === "trace" && !keypath) || !["trace", "scan"].includes(cmd)) {
  console.error(`cédula — credential & config provenance tracer

  cedula trace <config.json> <key.path>   where does this value come from?
  cedula scan  <config.json>              list every externalized value

Never prints resolved secrets.`);
  process.exit(1);
}
if (cmd === "trace") trace(file, keypath);
else scan(file);
