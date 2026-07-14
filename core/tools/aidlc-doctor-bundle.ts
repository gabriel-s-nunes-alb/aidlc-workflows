// aidlc-doctor-bundle.ts — the `/aidlc --doctor --bundle` diagnostic exporter.
//
// When a workflow misbehaves (a gate that will not open, a stage that will not
// advance, an approved report repeatedly refused) debugging today means asking
// the user for their whole project directory: huge, leaky (the record dir holds
// requirements/designs/decisions), and unmastigated (the maintainer hand-
// reconstructs the run from state + audit + markers + graph).
//
// This module produces the OPPOSITE: a small, redacted, self-diagnosing bundle.
// The value is the diagnosis, not raw file collection. It draws every finding
// from the SAME shared DoctorFinding model the live `--doctor` uses (the caller
// passes them in), so the command and the bundle can never develop separate
// diagnostic rules or remediation text.
//
// What it writes into a canonical bundle directory:
//   - report.md      — human-readable timeline + findings
//   - report.json    — machine-readable timeline + findings + summary
//   - manifest.json  — schema/versions, hashed intent id, included files,
//                      applied redactions, per-file checksums, truncations
//   - evidence/…     — NORMALIZED, allowlisted fields only (never raw files,
//                      never artifact/contribution/question/memory bodies)
//
// Packaging is best-effort and dependency-free: the canonical directory is the
// contract; a `.tar.gz` is produced when a system `tar` is available, else the
// directory is retained with manual-share instructions. No bespoke tar writer,
// no archive parser, no new package dependency.
//
// SAFETY: redaction runs before any file is written. Home → ~, project root →
// <project>, intent/unit ids → stable short hashes, and every emitted string is
// scanned for absolute paths and secret-like values. Symlinks are never
// followed; per-file and total size are capped; files are created owner-only
// where the platform supports it.

import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import {
  auditBlockField,
  docsRoot,
  hooksHealthDir,
  isoTimestamp,
  parseCheckboxes,
  planFilePath,
  readAllAuditShards,
  recordDir,
  recoveryFilePath,
  relativeRecordDir,
  runtimeGraphPath,
  stateFilePath,
  stopHookDir,
} from "./aidlc-lib.ts";
import { AIDLC_VERSION } from "./aidlc-version.ts";

// The bundle format version — bumped when the report/manifest/evidence SHAPE
// changes so a maintainer reading an old bundle knows what to expect.
export const BUNDLE_SCHEMA_VERSION = "1";

// Caps. A diagnostic bundle should never approach the size of the thing it is
// meant to replace; a runaway audit or a pathological graph is truncated with a
// recorded notice rather than copied whole.
export const MAX_EVIDENCE_FILE_BYTES = 512 * 1024; // 512 KiB per emitted file
export const MAX_BUNDLE_BYTES = 8 * 1024 * 1024; // 8 MiB total

// A stage whose observed duration exceeds this is flagged "abnormally long" in
// the timeline. Advisory only — it never changes a finding severity.
export const LONG_STAGE_MS = 6 * 60 * 60 * 1000; // 6h

// ===========================================================================
// Shared diagnostic model
// ===========================================================================

export type Severity = "info" | "warning" | "error";

// The single structured finding shape shared by the live doctor report and the
// exported bundle (issue #575 "Shared Diagnostic Model"). `evidence` carries
// only structural, allowlisted facts — never file bodies or secret-bearing
// text. `safeToAutomate` is false for every recovery-bypass remedy.
export interface DoctorFinding {
  id: string;
  severity: Severity;
  summary: string;
  evidence: Record<string, unknown>;
  remedy: string;
  safeToAutomate: boolean;
}

// The legacy pass/label/fix row handleDoctor builds today. Kept as the live
// render's shape; adaptLegacyResult() lifts one into a DoctorFinding so the
// bundle and the live report share findings without rewriting every check.
export interface LegacyDoctorResult {
  pass: boolean;
  label: string;
  fix?: string;
}

// Derive a stable, slug-shaped finding id from a legacy label. The label's
// leading phrase (up to the first ":" / "(" / "—") names the check; we
// kebab-case it so ids are stable across runs and readable in the manifest.
export function findingIdFromLabel(label: string): string {
  const head = label.split(/[:(—]/)[0].trim().toLowerCase();
  const slug = head
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug.length > 0 ? slug : "check";
}

// Lift a legacy {pass,label,fix} row into the shared model. A failed row is an
// error; a passing row with an advisory "(advisory)" tag is a warning; every
// other passing row is info. A recovery-bypass remedy (names an
// AIDLC_DISABLE_* env or "archive your workspace") is never safe to automate.
export function adaptLegacyResult(r: LegacyDoctorResult): DoctorFinding {
  const advisory = /\(advisory\)/i.test(r.label);
  const severity: Severity = !r.pass ? "error" : advisory ? "warning" : "info";
  const remedy = r.fix ?? "";
  return {
    id: findingIdFromLabel(r.label),
    severity,
    summary: r.label,
    evidence: {},
    remedy,
    safeToAutomate: severity === "info" ? true : !isRecoveryBypass(remedy),
  };
}

// A remedy is a recovery bypass when it instructs the operator to skip a guard
// or discard state — it must always carry a warning and never be automated.
export function isRecoveryBypass(remedy: string): boolean {
  return (
    /AIDLC_DISABLE_[A-Z_]+/.test(remedy) ||
    /\barchive your workspace\b/i.test(remedy) ||
    /\bstart a fresh workflow\b/i.test(remedy)
  );
}

// ===========================================================================
// Redaction
// ===========================================================================

// A short, stable hash used to replace an identifying token (intent slug, unit
// id) so two occurrences of the same id stay correlatable in the bundle while
// the original value never appears.
export function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 8);
}

export interface RedactionContext {
  projectDir: string;
  home: string;
  // Literal id → its stable short hash. Intent slugs and unit ids are seeded
  // here so filenames and inline references redact consistently.
  idHashes: Map<string, string>;
  // Names of the redaction rules actually applied (for the manifest).
  rulesApplied: Set<string>;
}

export function newRedactionContext(projectDir: string): RedactionContext {
  return {
    projectDir,
    home: homedir(),
    idHashes: new Map(),
    rulesApplied: new Set(),
  };
}

// Secret-like token shapes. Deliberately broad: AWS keys, bearer/JWT-ish
// blobs, generic `key=`/`token=`/`secret=`/`password=` assignments, and long
// hex/base64 runs. A false positive redacts a harmless string (acceptable); a
// miss leaks a secret (not). Applied to every emitted string.
const SECRET_PATTERNS: Array<{ rule: string; re: RegExp; replace: string }> = [
  { rule: "aws-access-key", re: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, replace: "<redacted-aws-key>" },
  { rule: "bearer-token", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/g, replace: "Bearer <redacted-token>" },
  { rule: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, replace: "<redacted-jwt>" },
  {
    rule: "assignment-secret",
    re: /\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['"]?[A-Za-z0-9._~+/=-]{6,}['"]?/gi,
    replace: "$1=<redacted>",
  },
  { rule: "long-hex-or-b64", re: /\b[A-Fa-f0-9]{40,}\b/g, replace: "<redacted-hex>" },
];

// Redact one string: home dir → ~, project root → <project>, seeded ids → their
// hashes, then the secret scan. Order matters — path normalization first so a
// home-prefixed secret path is caught by both rules. Records which rules fired.
export function redactString(value: string, ctx: RedactionContext): string {
  let out = value;
  // Project root before home: the project dir is usually deeper than home, so
  // replacing it first avoids a half-replaced "~/.../project" fragment.
  if (ctx.projectDir && out.includes(ctx.projectDir)) {
    out = out.split(ctx.projectDir).join("<project>");
    ctx.rulesApplied.add("project-root");
  }
  if (ctx.home && out.includes(ctx.home)) {
    out = out.split(ctx.home).join("~");
    ctx.rulesApplied.add("home-dir");
  }
  for (const [id, hash] of ctx.idHashes) {
    if (id.length >= 4 && out.includes(id)) {
      out = out.split(id).join(`<id:${hash}>`);
      ctx.rulesApplied.add("intent-id");
    }
  }
  for (const { rule, re, replace } of SECRET_PATTERNS) {
    if (re.test(out)) {
      ctx.rulesApplied.add(`secret:${rule}`);
      out = out.replace(re, replace);
    }
    re.lastIndex = 0;
  }
  return out;
}

// Deep-redact a JSON-able value: strings pass through redactString, arrays and
// plain objects recurse. Object KEYS are left intact (they are allowlisted
// field names, not user data); only values are scrubbed.
export function redactValue(value: unknown, ctx: RedactionContext): unknown {
  if (typeof value === "string") return redactString(value, ctx);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, ctx));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactValue(v, ctx);
    return out;
  }
  return value;
}

// ===========================================================================
// Timeline reconstruction (from audit shards)
// ===========================================================================

// One parsed audit event: the event name plus its whole block (for field
// lookups) and the parsed timestamp in epoch ms (NaN when unparseable).
interface AuditEvent {
  event: string;
  timestampMs: number;
  timestampRaw: string;
  block: string;
}

// Split the merged audit buffer into events. Blocks are separated by a blank
// line; the event name and timestamp live as **Event**/**Timestamp** fields.
// Chronological order follows the recorded timestamps (readAllAuditShards
// already merge-sorts), with unparseable timestamps kept in buffer order.
export function parseAuditEvents(audit: string): AuditEvent[] {
  const events: AuditEvent[] = [];
  if (!audit.trim()) return events;
  for (const block of audit.split(/\n\s*\n/)) {
    const event = auditBlockField(block, "Event");
    if (!event) continue;
    const tsRaw = auditBlockField(block, "Timestamp") ?? "";
    const ms = tsRaw ? Date.parse(tsRaw) : NaN;
    events.push({ event, timestampMs: ms, timestampRaw: tsRaw, block });
  }
  return events;
}

// A "?" literal is the report's honest representation of missing evidence —
// the timeline never infers an event that was not recorded.
export const UNKNOWN = "unknown";

export interface StageTimelineEntry {
  slug: string;
  startedRaw: string | typeof UNKNOWN;
  completedRaw: string | typeof UNKNOWN;
  durationMs: number | null; // null when either endpoint is unknown
  gate: "approved" | "rejected" | "unresolved" | "none";
  revisionCount: number | null;
  reviewerOutcome: "READY" | "NOT-READY" | "none" | typeof UNKNOWN;
  reviewerIterations: number | null;
  gapFromPrevMs: number | null; // time between previous stage's end and this start
  abnormal: string[]; // e.g. ["long-duration"], ["incomplete"]
}

export interface Timeline {
  stages: StageTimelineEntry[];
  workflowStartedRaw: string | typeof UNKNOWN;
  workflowStatus: string; // from state file, or "unknown"
  notes: string[];
}

// Reconstruct the stage timeline from the audit events + the state checkboxes.
// Every field that was not recorded is `unknown`/null — the report must not
// invent transitions. `stateContent` supplies the current status and the
// checkbox for a stage whose STAGE_COMPLETED never landed (incomplete).
export function reconstructTimeline(audit: string, stateContent: string): Timeline {
  const events = parseAuditEvents(audit);
  const notes: string[] = [];

  const workflowStarted = events.find((e) => e.event === "WORKFLOW_STARTED");
  const status = stateContent ? extractStatus(stateContent) : UNKNOWN;

  // Group events by stage slug (the **Stage** field, or **Slug** on some
  // events). Order-preserving so first-STARTED / last-COMPLETED are stable.
  const byStage = new Map<string, AuditEvent[]>();
  const stageOrder: string[] = [];
  for (const e of events) {
    const slug = auditBlockField(e.block, "Stage") ?? auditBlockField(e.block, "Slug");
    if (!slug) continue;
    if (!byStage.has(slug)) {
      byStage.set(slug, []);
      stageOrder.push(slug);
    }
    byStage.get(slug)!.push(e);
  }

  const checkboxes = stateContent ? parseCheckboxes(stateContent) : [];
  const checkboxBySlug = new Map(checkboxes.map((c) => [c.slug, c]));

  const stages: StageTimelineEntry[] = [];
  let prevEndMs: number | null = null;
  for (const slug of stageOrder) {
    const evs = byStage.get(slug)!;
    const started = firstEvent(evs, "STAGE_STARTED");
    const completed = lastEvent(evs, "STAGE_COMPLETED");
    const startedMs = started?.timestampMs ?? NaN;
    const completedMs = completed?.timestampMs ?? NaN;

    const durationMs =
      Number.isFinite(startedMs) && Number.isFinite(completedMs)
        ? completedMs - startedMs
        : null;

    // Gate: the last gate-resolution event for this stage, else "unresolved"
    // when the stage started but never completed and its checkbox is awaiting
    // approval, else "none".
    const gate = gateOutcome(evs, checkboxBySlug.get(slug)?.state);

    // Revision count: STAGE_REVISING occurrences, or the state field when the
    // stage is the current one. Null when neither is available.
    const revisions = evs.filter((e) => e.event === "STAGE_REVISING").length;
    const revisionCount = revisions > 0 ? revisions : completed || started ? 0 : null;

    // Reviewer: derived from recorded review outcome fields when present.
    const { outcome, iterations } = reviewerSignal(evs);

    const gapFromPrevMs =
      prevEndMs !== null && Number.isFinite(startedMs) ? startedMs - prevEndMs : null;

    const abnormal: string[] = [];
    if (durationMs !== null && durationMs > LONG_STAGE_MS) abnormal.push("long-duration");
    if (started && !completed) abnormal.push("incomplete");

    stages.push({
      slug,
      startedRaw: started?.timestampRaw ?? UNKNOWN,
      completedRaw: completed?.timestampRaw ?? UNKNOWN,
      durationMs,
      gate,
      revisionCount,
      reviewerOutcome: outcome,
      reviewerIterations: iterations,
      gapFromPrevMs,
      abnormal,
    });

    if (Number.isFinite(completedMs)) prevEndMs = completedMs;
  }

  if (events.length === 0) notes.push("No audit events found — timeline is empty.");
  if (stateContent === "") notes.push("No state file — status and checkbox cross-checks skipped.");

  return {
    stages,
    workflowStartedRaw: workflowStarted?.timestampRaw ?? UNKNOWN,
    workflowStatus: status,
    notes,
  };
}

function firstEvent(evs: AuditEvent[], name: string): AuditEvent | undefined {
  return evs.find((e) => e.event === name);
}
function lastEvent(evs: AuditEvent[], name: string): AuditEvent | undefined {
  for (let i = evs.length - 1; i >= 0; i--) if (evs[i].event === name) return evs[i];
  return undefined;
}

function extractStatus(stateContent: string): string {
  const m = stateContent.match(/^- \*\*Status\*\*:\s*(\S+)/m);
  return m ? m[1] : UNKNOWN;
}

// Gate outcome for a stage: the LAST gate-resolution event wins. When the stage
// started but no resolution was recorded and its checkbox is still awaiting
// approval, the gate is genuinely "unresolved" (the debugging signal). No gate
// event at all → "none".
function gateOutcome(
  evs: AuditEvent[],
  checkboxState: string | undefined,
): StageTimelineEntry["gate"] {
  let last: "approved" | "rejected" | null = null;
  for (const e of evs) {
    if (e.event === "GATE_APPROVED") last = "approved";
    else if (e.event === "GATE_REJECTED") last = "rejected";
  }
  if (last) return last;
  const awaited = evs.some((e) => e.event === "STAGE_AWAITING_APPROVAL");
  if (awaited || checkboxState === "awaiting-approval") return "unresolved";
  return "none";
}

// Reviewer signal from recorded events. The review outcome is carried on the
// STAGE_COMPLETED/AWAITING blocks as a **Review** field on harnesses that
// record it; iterations come from a **Review Iterations** field. Absent →
// unknown/null (never inferred).
function reviewerSignal(evs: AuditEvent[]): {
  outcome: StageTimelineEntry["reviewerOutcome"];
  iterations: number | null;
} {
  let outcome: StageTimelineEntry["reviewerOutcome"] = "none";
  let iterations: number | null = null;
  for (const e of evs) {
    const review = auditBlockField(e.block, "Review");
    if (review) {
      const up = review.toUpperCase();
      if (up.includes("NOT-READY") || up.includes("NOT READY")) outcome = "NOT-READY";
      else if (up.includes("READY")) outcome = "READY";
    }
    const iter = auditBlockField(e.block, "Review Iterations");
    if (iter && /^\d+$/.test(iter.trim())) iterations = Number(iter.trim());
  }
  return { outcome, iterations };
}

// ===========================================================================
// Deterministic diagnosis (fixed condition → remedy rules; NO LLM)
// ===========================================================================
//
// Each rule inspects the reconstructed timeline + on-disk evidence and, when
// its condition holds, emits a DoctorFinding with a FIXED remedy string. The
// rules are versioned by BUNDLE_SCHEMA_VERSION; adding/changing one is a
// deliberate, reviewed edit — never model-generated text at runtime.

// Inputs a diagnosis rule may read. Everything here is already redaction-safe
// to summarize structurally (ids are hashed before display; no bodies).
export interface DiagnosisInput {
  projectDir: string;
  timeline: Timeline;
  stateContent: string;
  audit: string;
  graphStages: GraphStageLite[]; // from runtime-graph.json (or [] when absent)
  recordAbsDir: string | null; // for structural contribution-file checks
  hooksHealth: HookHealthSnapshot;
  runtimeGraphExists: boolean;
  runtimeGraphMtimeMs: number | null;
  authoredInputsNewestMtimeMs: number | null; // newest stage-source mtime
  markers: MarkerSnapshot;
}

export interface GraphStageLite {
  slug: string;
  phase: string;
  mode: string;
  support_agents: string[];
}

export interface HookHealthSnapshot {
  dirExists: boolean;
  heartbeats: Array<{ hook: string; timestampRaw: string; ageMs: number | null }>;
  degradedDrops: Array<{ hook: string; count: number }>;
}

export interface MarkerSnapshot {
  planExists: boolean;
  planParseable: boolean | null; // null when absent
  recoveryExists: boolean;
  stopHookDirExists: boolean;
}

// Freshness window past which a heartbeat is "frozen" relative to the newest
// recorded audit activity. A hook that has not fired since well before the last
// stage transition is the cold-hook signal (#571's runtime-compile case).
export const FROZEN_HEARTBEAT_MS = 24 * 60 * 60 * 1000;

// Run every diagnosis rule. Order is severity-stable (errors first) only after
// sorting in the caller; here rules append in a fixed, readable order.
export function runDiagnosis(input: DiagnosisInput): DoctorFinding[] {
  const findings: DoctorFinding[] = [];
  const {
    timeline,
    graphStages,
    recordAbsDir,
    hooksHealth,
    runtimeGraphExists,
    runtimeGraphMtimeMs,
    authoredInputsNewestMtimeMs,
    markers,
    stateContent,
    audit,
  } = input;

  // Rule 1 — open / unresolved gates. A stage whose gate never resolved is the
  // single most common "it will not advance" cause.
  const unresolved = timeline.stages.filter((s) => s.gate === "unresolved");
  for (const s of unresolved) {
    findings.push({
      id: "gate-unresolved",
      severity: "error",
      summary: `Stage "${hashSlugForDisplay(s.slug)}" has an unresolved approval gate.`,
      evidence: {
        stage: hashSlugForDisplay(s.slug),
        gate: s.gate,
        startedAt: s.startedRaw,
        completed: s.completedRaw,
      },
      remedy:
        "The workflow is waiting at an approval gate. Resolve it with `/aidlc` " +
        "(answer the open question / approve or reject the stage), then continue.",
      safeToAutomate: false,
    });
  }

  // Rule 2 — ensemble evidence missing/malformed. STRUCTURAL ONLY: for every
  // graph stage that is a mob (or subagent-with-supports), check each declared
  // collaborator's contribution file for existence + identity-marker match.
  // Never reads or reports the file body or its first line's content.
  if (recordAbsDir) {
    for (const stage of graphStages) {
      const needs =
        stage.mode === "mob" ||
        (stage.mode === "subagent" && stage.support_agents.length > 0);
      if (!needs) continue;
      // Only diagnose a stage the run actually reached (started in the audit or
      // has a checkbox) — a not-yet-run ensemble stage is not a fault.
      const tl = timeline.stages.find((t) => t.slug === stage.slug);
      if (!tl) continue;
      const contribDir = join(recordAbsDir, stage.phase, stage.slug, "contributions");
      const problems: Array<Record<string, unknown>> = [];
      for (const agent of stage.support_agents) {
        const file = join(contribDir, `${agent}.md`);
        const st = safeLstat(file);
        if (!st || !st.isFile()) {
          problems.push({ collaborator: agent, exists: false, markerMatches: false });
          continue;
        }
        const markerMatches = firstLineIsMarker(file, agent);
        if (!markerMatches) {
          problems.push({
            collaborator: agent,
            exists: true,
            markerMatches: false,
            sizeBytes: st.size,
            mtime: new Date(st.mtimeMs).toISOString(),
          });
        }
      }
      if (problems.length > 0) {
        findings.push({
          id: "ensemble-evidence-missing",
          severity: "error",
          summary: `Ensemble stage "${hashSlugForDisplay(stage.slug)}" is missing or has malformed collaborator evidence.`,
          evidence: { stage: hashSlugForDisplay(stage.slug), mode: stage.mode, collaborators: problems },
          remedy:
            "Each declared collaborator must write its contribution file with the " +
            "identity-marker first line before approval. Dispatch the missing " +
            "collaborator(s) to write their contribution, then re-report. " +
            "WARNING: `AIDLC_DISABLE_ENSEMBLE_EVIDENCE=1` bypasses this validation " +
            "and is appropriate ONLY when legitimate evidence was lost — it must " +
            "never be automated.",
          safeToAutomate: false,
        });
      }
    }
  }

  // Rule 3 — state / audit disagreement. Audit says the workflow completed but
  // the state file does not (a torn write). Mirrors doctor's live drift check.
  if (audit.includes("**Event**: WORKFLOW_COMPLETED") && stateContent) {
    const status = extractStatus(stateContent);
    if (status !== "Completed" && status !== UNKNOWN) {
      findings.push({
        id: "state-audit-drift",
        severity: "error",
        summary: `Audit recorded WORKFLOW_COMPLETED but state Status=${status}.`,
        evidence: { auditEvent: "WORKFLOW_COMPLETED", stateStatus: status },
        remedy:
          "A state write was lost after the audit event landed. Set Status=Completed " +
          "in aidlc-state.md, or restart the workflow if the state is otherwise inconsistent.",
        safeToAutomate: false,
      });
    }
  }

  // Rule 4 — runtime graph older than its authored inputs. A stale graph means
  // a recompile did not run (the #571 cold-hook downstream). Only when both
  // mtimes are known.
  if (
    runtimeGraphExists &&
    runtimeGraphMtimeMs !== null &&
    authoredInputsNewestMtimeMs !== null &&
    authoredInputsNewestMtimeMs > runtimeGraphMtimeMs
  ) {
    findings.push({
      id: "runtime-graph-stale",
      severity: "warning",
      summary: "runtime-graph.json is older than its authored stage inputs.",
      evidence: {
        runtimeGraphMtime: new Date(runtimeGraphMtimeMs).toISOString(),
        authoredInputsNewestMtime: new Date(authoredInputsNewestMtimeMs).toISOString(),
      },
      remedy:
        "The compiled runtime graph is out of date. Re-run `bun " +
        "<harness>/tools/aidlc-graph.ts compile`; if this recurs, the " +
        "runtime-compile hook may not be firing on this harness (check hook heartbeats).",
      safeToAutomate: true,
    });
  } else if (!runtimeGraphExists) {
    findings.push({
      id: "runtime-graph-missing",
      severity: "warning",
      summary: "runtime-graph.json is missing for the active workflow.",
      evidence: { runtimeGraphExists: false },
      remedy:
        "No compiled runtime graph. Re-run `bun <harness>/tools/aidlc-graph.ts compile`. " +
        "If it never appears, the runtime-compile hook is not firing on this harness.",
      safeToAutomate: true,
    });
  }

  // Rule 5 — frozen / missing hook heartbeats. A registered hook that has not
  // fired since well before the latest audit activity is cold.
  if (!hooksHealth.dirExists) {
    findings.push({
      id: "hooks-never-fired",
      severity: "info",
      summary: "No hook heartbeats yet (fresh install or hooks not registered).",
      evidence: { healthDirExists: false },
      remedy: "If a workflow has run, verify hooks are registered in the harness wiring config.",
      safeToAutomate: true,
    });
  } else {
    for (const hb of hooksHealth.heartbeats) {
      if (hb.ageMs !== null && hb.ageMs > FROZEN_HEARTBEAT_MS) {
        findings.push({
          id: "hook-heartbeat-frozen",
          severity: "warning",
          summary: `Hook "${hb.hook}" has not fired in over ${Math.floor(hb.ageMs / (60 * 60 * 1000))}h.`,
          evidence: { hook: hb.hook, lastFired: hb.timestampRaw, ageMs: hb.ageMs },
          remedy:
            "A cold hook silently skips its side effects (audit, sensors, runtime " +
            "compile). Verify the hook is wired and firing on this harness.",
          safeToAutomate: true,
        });
      }
    }
    for (const d of hooksHealth.degradedDrops) {
      findings.push({
        id: "hook-degraded",
        severity: "error",
        summary: `Hook "${d.hook}" recorded ${d.count} degraded drop(s).`,
        evidence: { hook: d.hook, degradedCount: d.count },
        remedy:
          "A hook silently half-applied something (a dropped contribution or a failed " +
          "recompile). Inspect the hook's .drops file, fix the cause, and re-compose.",
        safeToAutomate: false,
      });
    }
  }

  // Rule 6 — missing / malformed runtime markers. A resolve output that cannot
  // be parsed will misroute the next `next`.
  if (markers.planExists && markers.planParseable === false) {
    findings.push({
      id: "plan-marker-malformed",
      severity: "error",
      summary: ".aidlc-plan.json is present but not parseable.",
      evidence: { planExists: true, planParseable: false },
      remedy:
        "The resolve output is corrupt. Re-run the resolve step (`/aidlc` will " +
        "recompute the plan), or remove .aidlc-plan.json to force a fresh resolve.",
      safeToAutomate: false,
    });
  }

  // Rule 7 — reviewer loop exhausted or incomplete. A stage that recorded a
  // NOT-READY as its last reviewer signal but never reached a resolved gate.
  for (const s of timeline.stages) {
    if (s.reviewerOutcome === "NOT-READY" && s.gate !== "approved") {
      findings.push({
        id: "reviewer-loop-incomplete",
        severity: "warning",
        summary: `Stage "${hashSlugForDisplay(s.slug)}" last reviewer verdict was NOT-READY and the gate is ${s.gate}.`,
        evidence: {
          stage: hashSlugForDisplay(s.slug),
          reviewerOutcome: s.reviewerOutcome,
          reviewerIterations: s.reviewerIterations,
          gate: s.gate,
        },
        remedy:
          "The reviewer left findings unresolved. Re-invoke the stage lead to address " +
          "the findings, or approve at the gate with the findings noted.",
        safeToAutomate: false,
      });
    }
  }

  return findings;
}

// Display form of a stage slug. CORE stage slugs identify framework behavior
// and are allowlisted to stay readable (issue #575); a non-core slug (a
// plugin/custom stage not in the shipped set) is hashed. The core set is
// derived from the graph stages passed in — anything present in the compiled
// graph is framework-known. Fallback: keep short slugs, hash the rest.
let _coreSlugs: Set<string> | null = null;
export function setCoreSlugs(slugs: Iterable<string>): void {
  _coreSlugs = new Set(slugs);
}
export function hashSlugForDisplay(slug: string): string {
  if (_coreSlugs && _coreSlugs.has(slug)) return slug;
  if (_coreSlugs === null) return slug; // no graph loaded → nothing to hash against
  return `<stage:${shortHash(slug)}>`;
}

function safeLstat(path: string): Stats | null {
  try {
    const st = lstatSync(path);
    if (st.isSymbolicLink()) return null; // never follow symlinks
    return st;
  } catch {
    return null;
  }
}

// Structural check ONLY: does the file's first line equal the collaborator
// identity marker? Returns a boolean — the content itself never leaves this
// function. Reads a bounded prefix so a huge file cannot blow memory.
function firstLineIsMarker(file: string, agent: string): boolean {
  try {
    const raw = readFileSync(file, "utf-8");
    const firstLine = raw.split("\n", 1)[0].trim();
    return firstLine === `**Collaborator:** ${agent}`;
  } catch {
    return false;
  }
}

// ===========================================================================
// Normalized evidence extraction (allowlisted fields — never raw files)
// ===========================================================================
//
// The evidence set is a set of small JSON documents built from ALLOWLISTED
// fields, not copies of the source files. Raw aidlc-state.md, audit shards,
// runtime-graph.json, and every artifact/contribution/question/memory body are
// EXPLICITLY excluded. Everything here is redacted before it is written.

// Selected state fields needed for routing + gate diagnosis. Naming these
// explicitly is the allowlist — a field not listed here never leaves the box.
const STATE_ALLOWLIST = [
  "State Version",
  "Status",
  "Scope",
  "Lifecycle Phase",
  "Current Stage",
  "Last Completed Stage",
  "Next Stage",
  "Active Agent",
  "Revision Count",
  "Parked",
  "Parked At Stage",
] as const;

// Audit event types that carry routing/gate signal. Other event types (and all
// free-text Details/Request fields) are dropped.
const AUDIT_EVENT_ALLOWLIST = new Set([
  "WORKFLOW_STARTED",
  "WORKFLOW_COMPLETED",
  "WORKFLOW_PARKED",
  "WORKFLOW_UNPARKED",
  "STAGE_STARTED",
  "STAGE_COMPLETED",
  "STAGE_AWAITING_APPROVAL",
  "STAGE_REVISING",
  "STAGE_SKIPPED",
  "GATE_APPROVED",
  "GATE_REJECTED",
  "HUMAN_TURN",
  "PHASE_STARTED",
  "PHASE_COMPLETED",
  "SCOPE_DETECTED",
  "SCOPE_CHANGED",
  "RECOMPOSED",
]);

// Audit block fields kept per event (structural only — no Details/Request/
// Reason free text, which can carry paths or decisions).
const AUDIT_FIELD_ALLOWLIST = ["Event", "Timestamp", "Stage", "Slug", "Phase", "Review", "Review Iterations"];

export interface NormalizedEvidence {
  state: Record<string, string>;
  auditEvents: Array<Record<string, string>>;
  graph: { stageCount: number; stages: GraphStageLite[] } | null;
  hooks: HookHealthSnapshot;
  markers: MarkerSnapshot & { turnCounter: string | null; readonlyLatch: boolean };
  timeline: Timeline;
}

// Extract state fields on the allowlist. Values are redacted by the caller.
export function extractStateFields(stateContent: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of STATE_ALLOWLIST) {
    const re = new RegExp(`^- \\*\\*${field.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\*\\*:\\s*(.*)$`, "m");
    const m = stateContent.match(re);
    if (m) out[field] = m[1].trim();
  }
  return out;
}

// Extract allowlisted audit events with allowlisted fields only.
export function extractAuditEvents(audit: string): Array<Record<string, string>> {
  const out: Array<Record<string, string>> = [];
  for (const e of parseAuditEvents(audit)) {
    if (!AUDIT_EVENT_ALLOWLIST.has(e.event)) continue;
    const row: Record<string, string> = {};
    for (const f of AUDIT_FIELD_ALLOWLIST) {
      const v = auditBlockField(e.block, f);
      if (v !== null) row[f] = v;
    }
    out.push(row);
  }
  return out;
}

// ===========================================================================
// Bundle assembly
// ===========================================================================

export interface BundleResult {
  bundleDir: string;
  archivePath: string | null; // .tar.gz when packaging succeeded, else null
  findings: DoctorFinding[];
  manualShareNote: string | null; // set when archiving was unavailable/failed
}

// A file staged for the bundle, with its redacted content. Written all at once
// after the size budget is checked so a truncation is recorded, not silent.
interface StagedFile {
  relPath: string;
  content: string;
  truncated: boolean;
}

// Build the full bundle. `liveFindings` are the shared-model findings the live
// doctor produced; `tsToken` is a filesystem-safe timestamp the CALLER stamps
// (isoTimestamp is unavailable to pass through pure code paths, so the caller
// provides it). Returns the bundle dir + archive path + findings.
export function buildBundle(
  projectDir: string,
  outParentDir: string,
  liveFindings: DoctorFinding[],
  tsToken: string,
): BundleResult {
  const ctx = newRedactionContext(projectDir);

  // Resolve the active record. Seed the intent slug into the redaction map so
  // it becomes a stable hash everywhere it appears.
  const recAbs = recordDir(projectDir);
  const relRec = relativeRecordDir(projectDir);
  const intentSlug = relRec ? basename(relRec) : null;
  const intentHash = intentSlug ? shortHash(intentSlug) : "no-intent";
  if (intentSlug) {
    ctx.idHashes.set(intentSlug, intentHash);
    ctx.rulesApplied.add("intent-id");
  }

  // Read sources (never emitted raw).
  const statePath = stateFilePath(projectDir);
  const stateContent = existsSync(statePath) ? safeRead(statePath) : "";
  const audit = readAllAuditShards(projectDir);

  // Runtime graph — structural stages + mtimes for the stale-graph rule.
  const rgPath = runtimeGraphPath(projectDir);
  const runtimeGraphExists = existsSync(rgPath);
  const runtimeGraphMtimeMs = runtimeGraphExists ? safeMtime(rgPath) : null;
  const graphStages = runtimeGraphExists ? readGraphStages(rgPath) : [];

  // Core stage slugs stay readable in the report (they identify framework
  // behavior, issue #575); non-core (plugin/custom) slugs are hashed. Seed the
  // core set from the SHIPPED stage-graph.json (always present in the harness
  // tree) — not the per-intent runtime graph, which may be missing (the very
  // thing we diagnose). The ensemble-evidence rule reads support_agents from
  // this same shipped graph when the runtime graph is absent.
  const shippedStages = readShippedStageGraph(projectDir);
  const stagesForDiagnosis = graphStages.length > 0 ? graphStages : shippedStages;
  setCoreSlugs(shippedStages.map((s) => s.slug));

  // Newest authored stage-source mtime (for the stale-graph comparison).
  const authoredNewest = newestStageSourceMtime(projectDir);

  // Hook health + markers.
  const hooksHealth = readHookHealth(projectDir, audit);
  const markers = readMarkers(projectDir);

  // Reconstruct timeline and run the deterministic diagnosis.
  const timeline = reconstructTimeline(audit, stateContent);
  const diagnosis = runDiagnosis({
    projectDir,
    timeline,
    stateContent,
    audit,
    graphStages: stagesForDiagnosis,
    recordAbsDir: recAbs,
    hooksHealth,
    runtimeGraphExists,
    runtimeGraphMtimeMs,
    authoredInputsNewestMtimeMs: authoredNewest,
    markers,
  });

  // Findings = live doctor findings + bundle-only diagnosis, deduped by id+
  // summary, errors first.
  const findings = mergeFindings(liveFindings, diagnosis);

  // Normalized, redacted evidence.
  const evidence: NormalizedEvidence = {
    state: extractStateFields(stateContent),
    auditEvents: extractAuditEvents(audit),
    graph: runtimeGraphExists ? { stageCount: graphStages.length, stages: graphStages } : null,
    hooks: hooksHealth,
    markers,
    timeline,
  };

  // Stage every file with redacted content.
  const staged: StagedFile[] = [];
  staged.push(stage("report.md", renderReportMd(timeline, findings, intentHash), ctx));
  staged.push(
    stage(
      "report.json",
      JSON.stringify({ schemaVersion: BUNDLE_SCHEMA_VERSION, timeline, findings }, null, 2),
      ctx,
    ),
  );
  staged.push(stage(join("evidence", "normalized.json"), JSON.stringify(evidence, null, 2), ctx));

  // Enforce the total-size budget across staged content, recording truncation.
  enforceTotalBudget(staged);

  // Manifest last — it checksums the OTHER files' final (redacted, truncated)
  // content. It is NOT re-redacted: its only strings are allowlisted field
  // names, the hashed intent id, and SHA-256 checksums (which the secret-scan
  // would otherwise mangle as "long hex"). Redaction already ran on every file
  // the manifest describes.
  const manifest = buildManifest(staged, ctx, intentHash);
  staged.push({ relPath: "manifest.json", content: JSON.stringify(manifest, null, 2), truncated: false });

  // Write the canonical directory (owner-only).
  const bundleDir = join(outParentDir, `aidlc-doctor-bundle-${tsToken}-${intentHash}`);
  writeBundleDir(bundleDir, staged);

  // Best-effort archive.
  const { archivePath, manualShareNote } = tryArchive(bundleDir, outParentDir, tsToken, intentHash);

  return { bundleDir, archivePath, findings, manualShareNote };
}

// --- staging + redaction + budget ------------------------------------------

function stage(relPath: string, rawContent: string, ctx: RedactionContext): StagedFile {
  let content = redactString(rawContent, ctx);
  let truncated = false;
  const bytes = Buffer.byteLength(content, "utf-8");
  if (bytes > MAX_EVIDENCE_FILE_BYTES) {
    // Truncate on a char boundary and append a recorded notice.
    content =
      content.slice(0, MAX_EVIDENCE_FILE_BYTES) +
      `\n\n[TRUNCATED: file exceeded ${MAX_EVIDENCE_FILE_BYTES} bytes]\n`;
    truncated = true;
  }
  return { relPath, content, truncated };
}

// Trim staged files from the largest down until the total fits the budget,
// recording each truncation. report.md/manifest are never dropped (they carry
// the notices), so only oversized evidence content is trimmed.
function enforceTotalBudget(staged: StagedFile[]): void {
  const total = () => staged.reduce((n, f) => n + Buffer.byteLength(f.content, "utf-8"), 0);
  if (total() <= MAX_BUNDLE_BYTES) return;
  const bySize = [...staged].sort(
    (a, b) => Buffer.byteLength(b.content, "utf-8") - Buffer.byteLength(a.content, "utf-8"),
  );
  for (const f of bySize) {
    if (total() <= MAX_BUNDLE_BYTES) break;
    if (f.relPath === "report.md") continue;
    const target = Math.max(1024, Math.floor(Buffer.byteLength(f.content, "utf-8") / 2));
    f.content = f.content.slice(0, target) + `\n[TRUNCATED: total-bundle budget]\n`;
    f.truncated = true;
  }
}

// --- manifest ---------------------------------------------------------------

interface Manifest {
  bundleSchemaVersion: string;
  aidlcVersion: string;
  harness: string;
  createdAt: string;
  intentIdHash: string;
  files: Array<{ path: string; sha256: string; bytes: number; truncated: boolean }>;
  redactionsApplied: string[];
  truncationNotices: string[];
  excluded: string[];
}

function buildManifest(staged: StagedFile[], ctx: RedactionContext, intentHash: string): Manifest {
  return {
    bundleSchemaVersion: BUNDLE_SCHEMA_VERSION,
    aidlcVersion: AIDLC_VERSION,
    harness: harnessTree(),
    createdAt: safeIso(),
    intentIdHash: intentHash,
    files: staged.map((f) => ({
      path: f.relPath,
      sha256: createHash("sha256").update(f.content, "utf-8").digest("hex"),
      bytes: Buffer.byteLength(f.content, "utf-8"),
      truncated: f.truncated,
    })),
    redactionsApplied: [...ctx.rulesApplied].sort(),
    truncationNotices: staged.filter((f) => f.truncated).map((f) => `${f.relPath} was truncated`),
    excluded: [
      "aidlc-state.md (raw)",
      "audit shards (raw)",
      "runtime-graph.json (raw)",
      "artifact bodies",
      "contribution bodies",
      "question/answer bodies",
      "memory files",
      "environment variables",
      "command output",
    ],
  };
}

// --- filesystem write (owner-only) -----------------------------------------

function writeBundleDir(bundleDir: string, staged: StagedFile[]): void {
  if (existsSync(bundleDir)) rmSync(bundleDir, { recursive: true, force: true });
  mkdirSync(bundleDir, { recursive: true });
  tryChmod(bundleDir, 0o700);
  for (const f of staged) {
    const abs = join(bundleDir, f.relPath);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, f.content, "utf-8");
    tryChmod(abs, 0o600);
  }
}

// --- archive (best-effort, dependency-free) --------------------------------

// Package the canonical dir as a .tar.gz using the system tar (present on
// macOS/Linux, and Windows 10+ ships bsdtar). No bespoke tar writer, no
// package dependency. On any failure the directory is retained and a manual-
// share note is returned instead.
function tryArchive(
  bundleDir: string,
  outParentDir: string,
  tsToken: string,
  intentHash: string,
): { archivePath: string | null; manualShareNote: string | null } {
  const archiveName = `aidlc-doctor-bundle-${tsToken}-${intentHash}.tar.gz`;
  const archivePath = join(outParentDir, archiveName);
  try {
    const dirName = basename(bundleDir);
    const res = Bun.spawnSync(["tar", "-czf", archivePath, "-C", outParentDir, dirName], {
      stdout: "ignore",
      stderr: "pipe",
    });
    if (res.exitCode === 0 && existsSync(archivePath)) {
      tryChmod(archivePath, 0o600);
      return { archivePath, manualShareNote: null };
    }
  } catch {
    // fall through to the directory-retained path
  }
  return {
    archivePath: null,
    manualShareNote:
      `Archiving is unavailable on this system. The diagnostic bundle directory was kept at:\n  ${bundleDir}\n` +
      `Compress it yourself (zip or tar) before sharing.`,
  };
}

// --- report.md --------------------------------------------------------------

function renderReportMd(timeline: Timeline, findings: DoctorFinding[], intentHash: string): string {
  const L: string[] = [];
  L.push(`# AI-DLC Diagnostic Bundle`);
  L.push("");
  L.push(`- Bundle schema: ${BUNDLE_SCHEMA_VERSION}`);
  L.push(`- AI-DLC version: ${AIDLC_VERSION}`);
  L.push(`- Harness: ${harnessTree()}`);
  L.push(`- Intent (hashed): ${intentHash}`);
  L.push(`- Workflow status: ${timeline.workflowStatus}`);
  L.push(`- Workflow started: ${timeline.workflowStartedRaw}`);
  L.push("");
  L.push(`No source files or artifact bodies are included. Identifiers are hashed and paths are redacted.`);
  L.push("");

  L.push(`## Findings`);
  L.push("");
  const errors = findings.filter((f) => f.severity === "error");
  const warnings = findings.filter((f) => f.severity === "warning");
  if (errors.length === 0 && warnings.length === 0) {
    L.push(`No errors or warnings.`);
  } else {
    for (const f of [...errors, ...warnings]) {
      L.push(`### ${f.severity.toUpperCase()} ${f.id}`);
      L.push("");
      L.push(f.summary);
      L.push("");
      if (f.remedy) {
        L.push(`Remedy: ${f.remedy}`);
        if (!f.safeToAutomate) L.push(`(Not safe to automate — run this yourself after confirming.)`);
        L.push("");
      }
    }
  }

  L.push(`## Timeline`);
  L.push("");
  if (timeline.stages.length === 0) {
    L.push(`No stages recorded.`);
  } else {
    L.push(`| Stage | Started | Completed | Duration | Gate | Rev | Reviewer | Gap | Flags |`);
    L.push(`|---|---|---|---|---|---|---|---|---|`);
    for (const s of timeline.stages) {
      L.push(
        `| ${hashSlugForDisplay(s.slug)} | ${s.startedRaw} | ${s.completedRaw} | ${fmtMs(s.durationMs)} | ${s.gate} | ${s.revisionCount ?? UNKNOWN} | ${s.reviewerOutcome}${s.reviewerIterations !== null ? `(${s.reviewerIterations})` : ""} | ${fmtMs(s.gapFromPrevMs)} | ${s.abnormal.join(",") || "-"} |`,
      );
    }
  }
  for (const n of timeline.notes) {
    L.push("");
    L.push(`> ${n}`);
  }
  L.push("");
  return L.join("\n");
}

function fmtMs(ms: number | null): string {
  if (ms === null) return UNKNOWN;
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  return `${Math.round((m / 60) * 10) / 10}h`;
}

// --- finding merge ----------------------------------------------------------

// Merge live-doctor findings with bundle diagnosis, dedup by id+summary, sort
// errors → warnings → info (stable within a bucket).
export function mergeFindings(live: DoctorFinding[], diagnosis: DoctorFinding[]): DoctorFinding[] {
  const seen = new Set<string>();
  const merged: DoctorFinding[] = [];
  for (const f of [...diagnosis, ...live]) {
    const key = `${f.id}::${f.summary}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(f);
  }
  const rank: Record<Severity, number> = { error: 0, warning: 1, info: 2 };
  return merged.sort((a, b) => rank[a.severity] - rank[b.severity]);
}

// --- source readers (structural only) --------------------------------------

// The shipped, always-present compiled stage graph (harness tree
// tools/data/stage-graph.json). Used to seed the core-slug allowlist and as
// the ensemble-mode source when the per-intent runtime graph is absent.
function readShippedStageGraph(projectDir: string): GraphStageLite[] {
  const p = join(projectDir, harnessTree(), "tools", "data", "stage-graph.json");
  if (!existsSync(p)) return [];
  return readGraphStages(p);
}

function readGraphStages(rgPath: string): GraphStageLite[] {
  try {
    const parsed = JSON.parse(safeRead(rgPath)) as unknown;
    const stages = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === "object" && Array.isArray((parsed as { stages?: unknown }).stages)
        ? (parsed as { stages: unknown[] }).stages
        : [];
    return (stages as Array<Record<string, unknown>>).map((s) => ({
      slug: typeof s.slug === "string" ? s.slug : "",
      phase: typeof s.phase === "string" ? s.phase : "",
      mode: typeof s.mode === "string" ? s.mode : "inline",
      support_agents: Array.isArray(s.support_agents) ? (s.support_agents as string[]) : [],
    })).filter((s) => s.slug !== "");
  } catch {
    return [];
  }
}

// Newest mtime across the authored stage source (aidlc-common/stages/**.md) —
// the "authored inputs" the runtime graph is compiled from.
function newestStageSourceMtime(projectDir: string): number | null {
  const root = join(projectDir, harnessTree(), "aidlc-common", "stages");
  let newest: number | null = null;
  const walk = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = join(dir, e);
      const st = safeLstat(abs);
      if (!st) continue;
      if (st.isDirectory()) walk(abs);
      else if (e.endsWith(".md") && (newest === null || st.mtimeMs > newest)) newest = st.mtimeMs;
    }
  };
  walk(root);
  return newest;
}

function readHookHealth(projectDir: string, audit: string): HookHealthSnapshot {
  const dir = hooksHealthDir(projectDir);
  const dirExists = existsSync(dir);
  const heartbeats: HookHealthSnapshot["heartbeats"] = [];
  const degradedDrops: HookHealthSnapshot["degradedDrops"] = [];
  // Age is measured against the newest audit timestamp (the run's own clock),
  // not wall-clock — a bundle produced days later must not flag every hook.
  const latestAudit = newestAuditMs(audit);
  if (dirExists) {
    let files: string[] = [];
    try {
      files = readdirSync(dir);
    } catch {
      return { dirExists, heartbeats, degradedDrops };
    }
    for (const f of files.filter((x) => x.endsWith(".last"))) {
      const tsRaw = safeRead(join(dir, f)).trim();
      const ms = tsRaw ? Date.parse(tsRaw) : NaN;
      const ageMs =
        Number.isFinite(ms) && latestAudit !== null ? Math.max(0, latestAudit - ms) : null;
      heartbeats.push({ hook: f.replace(/\.last$/, ""), timestampRaw: tsRaw || UNKNOWN, ageMs });
    }
    for (const f of files.filter((x) => x.endsWith(".drops"))) {
      const lines = safeRead(join(dir, f)).split("\n").filter((l) => l.includes("[degraded]"));
      if (lines.length > 0) degradedDrops.push({ hook: f.replace(/\.drops$/, ""), count: lines.length });
    }
  }
  return { dirExists, heartbeats, degradedDrops };
}

function readMarkers(projectDir: string): NormalizedEvidence["markers"] {
  const planPath = planFilePath(projectDir);
  const planExists = existsSync(planPath);
  let planParseable: boolean | null = null;
  if (planExists) {
    try {
      JSON.parse(safeRead(planPath));
      planParseable = true;
    } catch {
      planParseable = false;
    }
  }
  const stopDir = stopHookDir(projectDir);
  const turnCounterPath = join(docsRoot(projectDir), ".aidlc-turn-counter");
  const latchPath = join(docsRoot(projectDir), ".aidlc-readonly-latch");
  return {
    planExists,
    planParseable,
    recoveryExists: existsSync(recoveryFilePath(projectDir)),
    stopHookDirExists: existsSync(stopDir),
    turnCounter: existsSync(turnCounterPath) ? safeRead(turnCounterPath).trim() : null,
    readonlyLatch: existsSync(latchPath),
  };
}

function newestAuditMs(audit: string): number | null {
  let newest: number | null = null;
  for (const e of parseAuditEvents(audit)) {
    if (Number.isFinite(e.timestampMs) && (newest === null || e.timestampMs > newest)) {
      newest = e.timestampMs;
    }
  }
  return newest;
}

// --- small safe helpers -----------------------------------------------------

function safeRead(path: string): string {
  try {
    return readFileSync(path, "utf-8");
  } catch {
    return "";
  }
}

function safeMtime(path: string): number | null {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return null;
  }
}

function tryChmod(path: string, mode: number): void {
  try {
    chmodSync(path, mode);
  } catch {
    // Platforms without POSIX perms (Windows) — owner-only is best-effort.
  }
}

// isoTimestamp() reads a monotonic clock in the lib; safe to call at bundle
// time. Wrapped so a future clock-guard change has one call site.
function safeIso(): string {
  try {
    return isoTimestamp();
  } catch {
    return "unknown";
  }
}

// The harness tree dir (".claude"/".kiro"/".codex"). harnessTree resolves the
// same value harnessDir() does but is spelled here to avoid importing the
// display-only helper set; kept minimal.
function harnessTree(): string {
  // aidlc-lib's harnessDir() is the source of truth; re-derive via the tools
  // dir this module ships in. Fallback ".claude" matches the lib's default.
  const dir = import.meta.dir; // .../<harness>/tools
  const m = dir.match(/(\.[a-z]+)[/\\]tools[/\\]?$/);
  return m ? m[1] : ".claude";
}
