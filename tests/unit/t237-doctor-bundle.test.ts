// covers: subcommand:aidlc-utility:doctor
// covers: file:aidlc-doctor-bundle
//
// t237 - the `/aidlc --doctor --bundle` redacted diagnostic exporter (issue
// #575). Two mechanisms in one file:
//
//   1. PURE-HELPER unit assertions import the projected module directly
//      (dist/claude/.claude/tools/aidlc-doctor-bundle.ts — the same dist path
//      t204 imports aidlc-lib from) and exercise redactString /
//      reconstructTimeline / isRecoveryBypass / adaptLegacyResult in-process.
//
//   2. END-TO-END + SECRET-CANARY assertions SPAWN the real tool the way t204 /
//      t83 do (process.execPath running aidlc-utility.ts) with
//      `doctor --bundle --project-dir <p> --bundle-out <p>/out`, then walk the
//      produced bundle directory AND extract the .tar.gz to prove that no secret
//      canary — an AWS key, a password= assignment, a foreign home path, or the
//      raw intent slug — survives into ANY emitted file. The canary test is the
//      load-bearing safety contract: the bundle's entire reason to exist is that
//      it is safe to hand a maintainer.
//
// Fixture discipline mirrors t83: createTestProject() (no .claude copy — the
// shipped stage graph is simply absent, exactly as t83/t204 run), a per-test
// fresh project torn down in afterEach, audit seeded into a *.md shard the
// doctor globs via readAllAuditShards.

import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  AIDLC_SRC,
  cleanupTestProject,
  createTestProject,
} from "../harness/fixtures.ts";
import {
  adaptLegacyResult,
  isRecoveryBypass,
  newRedactionContext,
  reconstructTimeline,
  redactString,
  UNKNOWN,
} from "../../dist/claude/.claude/tools/aidlc-doctor-bundle.ts";

const BUN = process.execPath; // the bun running this test
const UTIL = join(AIDLC_SRC, "tools", "aidlc-utility.ts");

// Secret canaries — none of these may appear anywhere in the emitted bundle.
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const PASSWORD_SECRET = "supersecret123";
const HOME_PATH = "/Users/secretuser/DEV/proj";
const INTENT_SLUG = "build-auth-a1b2c3d4"; // the record-dir name → hashed

const created: string[] = [];
afterEach(() => {
  while (created.length) cleanupTestProject(created.pop());
});

function freshProject(): string {
  const proj = createTestProject();
  created.push(proj);
  return proj;
}

/**
 * Replace the default seeded intent with a record dir NAMED `build-auth-a1b2c3d4`
 * (so the intent slug the bundle hashes is our canary), seed it with a state file
 * carrying secret canaries in allowlisted fields (→ redacted) and non-allowlisted
 * fields (→ dropped) plus a `[?]` feasibility checkbox, and an audit shard whose
 * feasibility stage sits at STAGE_AWAITING_APPROVAL with no GATE_APPROVED (→ the
 * gate-unresolved diagnosis). Free-text audit fields carry the same canaries to
 * prove the field allowlist drops them.
 */
function seedCanaryIntent(proj: string): void {
  const intentsDir = join(proj, "aidlc", "spaces", "default", "intents");
  const recDir = join(intentsDir, INTENT_SLUG);
  mkdirSync(join(recDir, "audit"), { recursive: true });
  // Repoint the active-intent cursor at our named record.
  writeFileSync(join(intentsDir, "active-intent"), `${INTENT_SLUG}\n`, "utf-8");

  const state = [
    "# AI-DLC State Tracking",
    "",
    "## Project Information",
    // NON-allowlisted → dropped entirely (the foreign home path never emits).
    `- **Project Root**: ${HOME_PATH}`,
    // Allowlisted → extracted, then redacted.
    "- **Status**: InProgress",
    `- **Scope**: password=${PASSWORD_SECRET}`,
    `- **Active Agent**: ${AWS_KEY}`,
    // The raw slug in an allowlisted field: forces it through emission so the
    // intent-id hashing must fire (a redaction miss would leak it here).
    `- **Next Stage**: ${INTENT_SLUG}`,
    "- **State Version**: 7",
    "",
    "## Stage Progress",
    "### IDEATION PHASE",
    "- [?] feasibility — EXECUTE",
    "",
  ].join("\n");
  writeFileSync(join(recDir, "aidlc-state.md"), state, "utf-8");

  const audit = [
    "## Stage Started",
    "**Timestamp**: 2026-05-19T10:00:00Z",
    "**Event**: STAGE_STARTED",
    "**Stage**: feasibility",
    "",
    "## Stage Awaiting Approval",
    "**Timestamp**: 2026-05-19T11:00:00Z",
    "**Event**: STAGE_AWAITING_APPROVAL",
    "**Stage**: feasibility",
    "",
    // A non-allowlisted event with canaries in free-text fields — dropped whole.
    "## Subagent Completed",
    "**Timestamp**: 2026-05-19T09:00:00Z",
    "**Event**: SUBAGENT_COMPLETED",
    `**Details**: used ${AWS_KEY} with password=${PASSWORD_SECRET} under ${HOME_PATH}`,
    `**Message**: ${INTENT_SLUG}`,
    "",
  ].join("\n");
  writeFileSync(join(recDir, "audit", "seed.md"), audit, "utf-8");
}

interface BundleRun {
  status: number;
  out: string;
  outDir: string;
  bundleDir: string | null;
  archivePath: string | null;
}

/** Spawn `doctor --bundle` and locate the produced bundle dir + archive. */
function runBundle(proj: string): BundleRun {
  const outDir = join(proj, "out");
  const res = spawnSync(
    BUN,
    [UTIL, "doctor", "--bundle", "--project-dir", proj, "--bundle-out", outDir],
    { encoding: "utf-8", env: { ...process.env } },
  );
  let bundleDir: string | null = null;
  let archivePath: string | null = null;
  try {
    for (const e of readdirSync(outDir, { withFileTypes: true })) {
      if (e.isDirectory() && e.name.startsWith("aidlc-doctor-bundle-")) {
        bundleDir = join(outDir, e.name);
      } else if (e.isFile() && e.name.endsWith(".tar.gz")) {
        archivePath = join(outDir, e.name);
      }
    }
  } catch {
    /* outDir missing → bundle failed; leave nulls for the test to surface */
  }
  return {
    status: res.status ?? -1,
    out: `${res.stdout ?? ""}${res.stderr ?? ""}`,
    outDir,
    bundleDir,
    archivePath,
  };
}

/** Every regular file under a directory tree (absolute paths). */
function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walkFiles(p));
    else if (e.isFile()) out.push(p);
  }
  return out;
}

describe("t237 doctor --bundle diagnostic exporter (#575)", () => {
  test("1: SECRET CANARY — no secret survives into any bundle file or the archive", () => {
    const proj = freshProject();
    seedCanaryIntent(proj);
    const { bundleDir, archivePath } = runBundle(proj);
    expect(bundleDir).not.toBeNull();

    const canaries = [AWS_KEY, PASSWORD_SECRET, `password=${PASSWORD_SECRET}`, HOME_PATH, INTENT_SLUG];

    // (a) Every file on disk under the bundle dir is clean.
    for (const file of walkFiles(bundleDir!)) {
      const body = readFileSync(file, "utf-8");
      for (const c of canaries) {
        expect(body, `${c} leaked into ${file}`).not.toContain(c);
      }
    }

    // (b) The packaged .tar.gz is clean too (extract every member to stdout).
    expect(archivePath).not.toBeNull();
    const extracted = spawnSync("tar", ["-xzOf", archivePath!], { encoding: "utf-8" });
    expect(extracted.status).toBe(0);
    for (const c of canaries) {
      expect(extracted.stdout, `${c} leaked into the archive`).not.toContain(c);
    }
  }, 30000);

  test("2: bundle dir contains report.md, report.json, manifest.json, evidence/normalized.json", () => {
    const proj = freshProject();
    seedCanaryIntent(proj);
    const { bundleDir } = runBundle(proj);
    expect(bundleDir).not.toBeNull();
    const rel = walkFiles(bundleDir!).map((f) => f.slice(bundleDir!.length + 1).replace(/\\/g, "/"));
    expect(rel).toContain("report.md");
    expect(rel).toContain("report.json");
    expect(rel).toContain("manifest.json");
    expect(rel).toContain("evidence/normalized.json");
  }, 30000);

  test("3: report.json exposes findings + timeline.stages and the gate-unresolved error", () => {
    const proj = freshProject();
    seedCanaryIntent(proj);
    const { bundleDir } = runBundle(proj);
    expect(bundleDir).not.toBeNull();
    const report = JSON.parse(readFileSync(join(bundleDir!, "report.json"), "utf-8"));
    expect(Array.isArray(report.findings)).toBe(true);
    expect(Array.isArray(report.timeline.stages)).toBe(true);
    const gate = report.findings.find((f: { id: string }) => f.id === "gate-unresolved");
    expect(gate).toBeDefined();
    expect(gate.severity).toBe("error");
  }, 30000);

  test("4: manifest.json carries real sha256 checksums, versions, hashed intent id, excluded + files", () => {
    const proj = freshProject();
    seedCanaryIntent(proj);
    const { bundleDir } = runBundle(proj);
    expect(bundleDir).not.toBeNull();
    const manifest = JSON.parse(readFileSync(join(bundleDir!, "manifest.json"), "utf-8"));
    expect(typeof manifest.bundleSchemaVersion).toBe("string");
    expect(typeof manifest.aidlcVersion).toBe("string");
    expect(typeof manifest.intentIdHash).toBe("string");
    expect(Array.isArray(manifest.excluded)).toBe(true);
    // Raw bodies must be named as excluded.
    expect(manifest.excluded.join("\n")).toContain("aidlc-state.md (raw)");
    expect(Array.isArray(manifest.files)).toBe(true);
    expect(manifest.files.length).toBeGreaterThan(0);
    for (const f of manifest.files) {
      expect(f.sha256).toMatch(/^[0-9a-f]{64}$/); // real hash, never <redacted-hex>
      expect(f.sha256).not.toBe("<redacted-hex>");
    }
  }, 30000);

  test("5: redactString scrubs home, project dir, AWS key, and password= assignment", () => {
    const ctx = newRedactionContext("/tmp/my-secret-proj");
    const home = homedir();

    const redHome = redactString(`config lives at ${home}/.aidlc`, ctx);
    expect(redHome).toContain("~/.aidlc");
    expect(redHome).not.toContain(home);

    const redProj = redactString("/tmp/my-secret-proj/aidlc/state.md", ctx);
    expect(redProj).toContain("<project>");
    expect(redProj).not.toContain("/tmp/my-secret-proj");

    expect(redactString(AWS_KEY, ctx)).not.toContain(AWS_KEY);

    const redPw = redactString(`password=${PASSWORD_SECRET}`, ctx);
    expect(redPw).not.toContain(PASSWORD_SECRET);
    expect(redPw).toContain("<redacted>");
  });

  test("6: reconstructTimeline durations + gate for a complete stage, incomplete flag for a torn one", () => {
    const audit = [
      "## a started",
      "**Timestamp**: 2026-01-01T00:00:00Z",
      "**Event**: STAGE_STARTED",
      "**Stage**: stagea",
      "",
      "## a completed",
      "**Timestamp**: 2026-01-01T01:00:00Z",
      "**Event**: STAGE_COMPLETED",
      "**Stage**: stagea",
      "",
      "## a gate",
      "**Timestamp**: 2026-01-01T01:30:00Z",
      "**Event**: GATE_APPROVED",
      "**Stage**: stagea",
      "",
      "## b started",
      "**Timestamp**: 2026-01-01T02:00:00Z",
      "**Event**: STAGE_STARTED",
      "**Stage**: stageb",
      "",
    ].join("\n");

    const tl = reconstructTimeline(audit, "");
    const a = tl.stages.find((s) => s.slug === "stagea");
    const b = tl.stages.find((s) => s.slug === "stageb");
    expect(a).toBeDefined();
    expect(b).toBeDefined();
    // Complete stage: numeric duration (1h) and a resolved gate.
    expect(typeof a!.durationMs).toBe("number");
    expect(a!.durationMs).toBe(60 * 60 * 1000);
    expect(a!.gate).toBe("approved");
    expect(a!.abnormal).not.toContain("incomplete");
    // Torn stage: never completed → incomplete flag + unknown completion.
    expect(b!.abnormal).toContain("incomplete");
    expect(b!.completedRaw).toBe(UNKNOWN);
    expect(b!.durationMs).toBeNull();
  });

  test("7: isRecoveryBypass flags AIDLC_DISABLE_* remedies; adaptLegacyResult maps pass/fail severity", () => {
    expect(
      isRecoveryBypass("Set AIDLC_DISABLE_ENSEMBLE_EVIDENCE=1 to bypass the validation."),
    ).toBe(true);
    expect(isRecoveryBypass("Re-run the compile step and continue.")).toBe(false);

    const fail = adaptLegacyResult({ pass: false, label: "hooks wired", fix: "wire the hook" });
    expect(fail.severity).toBe("error");

    const ok = adaptLegacyResult({ pass: true, label: "bun installed" });
    expect(ok.severity).toBe("info");
    expect(ok.safeToAutomate).toBe(true);
  });
});
