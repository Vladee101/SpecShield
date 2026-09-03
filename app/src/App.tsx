/**
 * Workflow A, as a screen — PRD §12.
 *
 * Import → review → sanitize → **verify** → copy → paste response → restore.
 *
 * Two things the UI must never do, both enforced on the Rust side and mirrored
 * here so the interface cannot imply otherwise:
 *
 * 1. Show or offer to copy a twin that did not pass the gate. When the gate
 *    blocks, the backend returns no twin at all.
 * 2. Present "verified" as "safe". Every green state carries what was *not*
 *    checked (PRD §4.3), because the residual risk is the part users forget.
 */
import { useCallback, useEffect, useState } from "react";
import {
  api,
  type AppliedPatch,
  type AuditRow,
  type ExportSummary,
  type IndexSummary,
  type LocatedIdentity,
  type RecoveryReport,
  type RescanSummary,
  type RestoredProject,
  type UnifyProposal,
  type VerifyResult,
  type DiffReview,
  type EntityType,
  type PatchStatus,
  type ProjectInfo,
  type RestoreResult,
  type SanitizeResult,
  type ScanResult,
  type SecretSite,
} from "./api";

/// The workflow, in order. Numbered in the interface because they are meant to
/// be walked through.
type Step = "project" | "review" | "verify" | "restore" | "apply";

/// Everything that is not a workflow step. Kept visually separate: an audit log
/// is not step six of sanitizing a document, and numbering it alongside the
/// others would say it was.
type Tool = "project-ops" | "audit" | "vault";

type Screen = Step | Tool;

const STEPS: Step[] = ["project", "review", "verify", "restore", "apply"];
const STEP_LABELS: Record<Step, string> = {
  project: "Project",
  review: "Review",
  verify: "Sanitize & verify",
  restore: "Restore",
  apply: "Diff & apply",
};

const TOOLS: Tool[] = ["project-ops", "audit", "vault"];
const TOOL_LABELS: Record<Tool, string> = {
  "project-ops": "Whole project",
  audit: "Audit log",
  vault: "Vault",
};

const ENTITY_TYPES: EntityType[] = [
  "ORG", "SERVICE", "API", "ENDPOINT", "DB_TABLE", "COLUMN", "DTO",
  "IFACE", "ENUM", "EVENT", "INDEX", "ENV", "HOST", "PATH",
];

/// The document under review, held once at the top so Review and Sanitize
/// operate on the same text. Keeping a copy per panel meant a user reviewed one
/// document and sanitized whatever they happened to paste next — which is
/// exactly the mistake this tool exists to prevent.
interface Doc {
  filename: string;
  content: string;
}


/**
 * A path field with a Browse button — P1-3.
 *
 * The field stays editable. A picker is the convenient way to name a path, not
 * the only way: typing one is what someone reads out of a runbook, and the
 * dialog cannot name a directory that does not exist yet.
 */
function PathField({
  value,
  onChange,
  placeholder,
  onError,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  onError: (e: string | null) => void;
}) {
  return (
    <>
      <input
        className="grow mono"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        title="Choose a folder"
        onClick={async () => {
          onError(null);
          try {
            // null means cancelled, which is not an error and must not be
            // reported as one.
            const picked = await api.pickDirectory();
            if (picked !== null) onChange(picked);
          } catch (e) {
            onError(String(e));
          }
        }}
      >
        Browse…
      </button>
    </>
  );
}

export function App() {
  const [project, setProject] = useState<ProjectInfo | null>(null);
  const [step, setStep] = useState<Screen>("project");
  const [error, setError] = useState<string | null>(null);
  const [doc, setDoc] = useState<Doc>({ filename: "PRD.md", content: "" });
  /// The twin from the last sanitize that passed the gate, held here so the
  /// diff screen compares against what was actually sent rather than asking the
  /// user to paste it back and trust that they pasted the right thing.
  const [twin, setTwin] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setProject(await api.projectInfo());
    } catch {
      setProject(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div className="app">
      <header className="row" style={{ marginBottom: 18 }}>
        <div className="grow">
          <strong style={{ fontSize: 16 }}>SpecShield</strong>{" "}
          <span className="muted small">semantic gateway</span>
        </div>
        {project && (
          <div className="row small muted">
            <span className="tag">{project.name}</span>
            <span className="tag">{project.alias_style}</span>
            <span>{project.identity_count} identities</span>
            <button
              onClick={async () => {
                await api.closeProject();
                setProject(null);
                setStep("project");
              }}
            >
              Close
            </button>
          </div>
        )}
      </header>

      {project?.cloud_sync_warning && (
        <div className="banner warn">
          <strong>Cloud-synced location.</strong>
          <div className="small" style={{ marginTop: 4 }}>{project.cloud_sync_warning}</div>
        </div>
      )}

      {error && (
        <div className="banner block">
          <strong>Error</strong>
          <div className="small mono" style={{ marginTop: 4 }}>{error}</div>
        </div>
      )}

      <nav className="steps">
        {STEPS.map((s, i) => (
          <button
            key={s}
            className={`step ${step === s ? "active" : ""}`}
            disabled={s !== "project" && !project}
            onClick={() => setStep(s)}
          >
            {i + 1}. {STEP_LABELS[s]}
          </button>
        ))}
        <span className="nav-gap" />
        {TOOLS.map((t) => (
          <button
            key={t}
            className={`step ${step === t ? "active" : ""}`}
            disabled={!project}
            onClick={() => setStep(t)}
          >
            {TOOL_LABELS[t]}
          </button>
        ))}
      </nav>

      {step === "project" && (
        <ProjectPanel
          project={project}
          onOpened={(p) => {
            setProject(p);
            setStep("review");
          }}
          onError={setError}
        />
      )}
      {step === "review" && project && (
        <ReviewPanel
          doc={doc}
          setDoc={setDoc}
          onError={setError}
          onTermAdded={refresh}
          onReviewed={() => setStep("verify")}
        />
      )}
      {step === "verify" && project && (
        <SanitizePanel doc={doc} setDoc={setDoc} onError={setError} onDone={refresh} setTwin={setTwin} />
      )}
      {step === "restore" && project && <RestorePanel onError={setError} />}
      {step === "apply" && project && <DiffPanel doc={doc} twin={twin} onError={setError} />}
      {step === "project-ops" && project && (
        <ProjectOpsPanel
          onError={setError}
          onChanged={() => {
            // Export and unification both re-derive aliases, so the session's
            // twin may no longer restore and the header count is stale.
            setTwin(null);
            void refresh();
          }}
        />
      )}
      {step === "audit" && project && <AuditPanel onError={setError} />}
      {step === "vault" && project && (
        <VaultPanel
          onError={setError}
          onRekeyed={() => {
            // Every alias moved, so the session's twin is orphaned and the
            // identity count in the header is stale.
            setTwin(null);
            void refresh();
          }}
        />
      )}
    </div>
  );
}

function ProjectPanel({
  project,
  onOpened,
  onError,
}: {
  project: ProjectInfo | null;
  onOpened: (p: ProjectInfo) => void;
  onError: (e: string | null) => void;
}) {
  const [path, setPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [aliasStyle, setAliasStyle] = useState("typed");
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<ProjectInfo>) => {
    setBusy(true);
    onError(null);
    try {
      onOpened(await fn());
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Project</h3>
      <p className="muted small">
        The vault holds the mapping from alias back to real name. It never leaves this
        machine, and the passphrase is the only way to open it — there is no recovery.
      </p>

      <div style={{ display: "grid", gap: 10, maxWidth: 560 }}>
        <label>
          <div className="small muted">Project folder</div>
          <div className="row">
            <PathField value={path} onChange={setPath} placeholder="C:\work\billing" onError={onError} />
          </div>
        </label>
        <label>
          <div className="small muted">Passphrase</div>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="used to derive the vault key"
          />
        </label>
        <label>
          <div className="small muted">Alias style (new projects only — changing it later needs a re-key)</div>
          <select value={aliasStyle} onChange={(e) => setAliasStyle(e.target.value)}>
            <option value="typed">Typed — PrimaryService_H7K2Q3 (recommended)</option>
            <option value="opaque">Opaque — SERVICE_H7K2Q3 (strongest)</option>
            <option value="pseudonymous">Pseudonymous — AuroraService (most readable)</option>
          </select>
        </label>

        <div className="row">
          <button
            className="primary"
            disabled={busy || !path || !passphrase}
            onClick={() => void run(() => api.openProject(path, passphrase))}
          >
            Open
          </button>
          <button
            disabled={busy || !path || !passphrase}
            onClick={() => void run(() => api.createProject(path, passphrase, aliasStyle))}
          >
            Create new
          </button>
        </div>
      </div>

      {project && (
        <p className="small muted" style={{ marginBottom: 0 }}>
          Open: <strong>{project.name}</strong> — {project.identity_count} identities,{" "}
          {project.term_count} dictionary terms.
        </p>
      )}
    </div>
  );
}

function ReviewPanel({
  doc,
  setDoc,
  onError,
  onTermAdded,
  onReviewed,
}: {
  doc: Doc;
  setDoc: (d: Doc) => void;
  onError: (e: string | null) => void;
  onTermAdded: () => void;
  onReviewed: () => void;
}) {
  const { filename, content } = doc;
  const setFilename = (f: string) => setDoc({ ...doc, filename: f });
  const setContent = (c: string) => setDoc({ ...doc, content: c });
  const [result, setResult] = useState<ScanResult | null>(null);
  const [term, setTerm] = useState("");
  const [termType, setTermType] = useState<EntityType>("ORG");

  const scan = async () => {
    onError(null);
    try {
      setResult(await api.scan(filename, content));
    } catch (e) {
      setResult(null);
      onError(String(e));
    }
  };

  return (
    <>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Review</h3>
        <p className="muted small">
          See what would be aliased before anything is. Names no rule can recognise —
          your company, your customers — come from the dictionary; add them once and
          they are found everywhere afterwards.
        </p>
        <div className="row" style={{ marginBottom: 10 }}>
          <input
            className="grow"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            placeholder="filename, e.g. PRD.md"
          />
          <button
            onClick={async () => {
              onError(null);
              try {
                const picked = await api.pickFile();
                if (picked) setDoc({ filename: picked.name, content: picked.content });
              } catch (e) {
                onError(String(e));
              }
            }}
          >
            Open file…
          </button>
          <button onClick={() => void scan()} disabled={!content}>Scan</button>
        </div>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste the document here…"
        />
      </div>

      <div className="panel">
        <h4 style={{ marginTop: 0 }}>Dictionary</h4>
        <div className="row">
          <input
            className="grow"
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder="a name only you can identify, e.g. your company"
          />
          <select style={{ width: 140 }} value={termType} onChange={(e) => setTermType(e.target.value as EntityType)}>
            {ENTITY_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <button
            disabled={!term}
            onClick={async () => {
              onError(null);
              try {
                await api.addTerm(term, termType);
                setTerm("");
                onTermAdded();
                await scan();
              } catch (e) {
                onError(String(e));
              }
            }}
          >
            Add
          </button>
        </div>
      </div>

      {result && (
        <div className="panel">
          <div className="row" style={{ marginBottom: 8 }}>
            <h4 style={{ margin: 0 }} className="grow">
              {result.entities.length} would be aliased
            </h4>
            <span className="tag">{result.parser}</span>
            {/* The review step had no exit. Reviewing and then hunting for the
                next tab is how a user ends up sanitizing a document they never
                reviewed. */}
            <button className="primary" onClick={onReviewed}>
              Sanitize this →
            </button>
          </div>

          <div className="scroll">
            <table>
              <thead>
                <tr><th>Type</th><th>Name</th><th>Offset</th></tr>
              </thead>
              <tbody>
                {result.entities.map((e, i) => (
                  <tr key={i}>
                    <td><span className="tag">{e.entity_type}</span></td>
                    <td className="mono">{e.real_name}</td>
                    <td className="mono muted">{e.byte_start}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {result.suggestions.length > 0 && (
            <>
              <h4>{result.suggestions.length} suggestions — not applied</h4>
              <p className="small muted">
                Below the confidence floor. Nothing here is aliased unless you confirm it
                as a dictionary term.
              </p>
              <div className="scroll">
                <table>
                  <tbody>
                    {result.suggestions.map((s, i) => (
                      <tr key={i}>
                        <td className="mono">{s.real_name}</td>
                        <td className="muted">{s.entity_type}</td>
                        <td className="muted">{s.confidence.toFixed(2)}</td>
                        <td>
                          <button
                            onClick={async () => {
                              // The detector already classified this. Confirming
                              // as ORG regardless — which is what this did —
                              // gave a service the organization prefix and put a
                              // wrong category in front of the model.
                              await api.addTerm(s.real_name, s.entity_type as EntityType);
                              onTermAdded();
                              await scan();
                            }}
                          >
                            Confirm
                          </button>
                          <button
                            style={{ marginLeft: 6 }}
                            onClick={async () => {
                              await api.addAllowed(s.real_name);
                              await scan();
                            }}
                          >
                            Never alias
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {result.secrets.length > 0 && (
            <>
              <h4>{result.secrets.length} secrets — redacted one-way</h4>
              <p className="small muted">
                Secrets are never restored. A credential put back into generated code
                would be worse than useless.
              </p>
              <table>
                <tbody>
                  {result.secrets.map((s, i) => (
                    <tr key={i}>
                      <td className="mono">{s.secret_type}</td>
                      <td className="muted">line {s.line}</td>
                      <td>{s.blocking ? <span className="error">blocks export</span> : <span className="muted">review</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}
    </>
  );
}

function SanitizePanel({
  doc,
  setDoc,
  onError,
  onDone,
  setTwin,
}: {
  doc: Doc;
  setDoc: (d: Doc) => void;
  onError: (e: string | null) => void;
  onDone: () => void;
  setTwin: (twin: string | null) => void;
}) {
  const { filename, content } = doc;
  const setFilename = (f: string) => setDoc({ ...doc, filename: f });
  const setContent = (c: string) => setDoc({ ...doc, content: c });
  const [result, setResult] = useState<SanitizeResult | null>(null);
  const [copied, setCopied] = useState<number | null>(null);
  const [savedTo, setSavedTo] = useState<string | null>(null);

  return (
    <>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Sanitize &amp; verify</h3>
        <div className="row" style={{ marginBottom: 10 }}>
          <input className="grow" value={filename} onChange={(e) => setFilename(e.target.value)} />
          <button
            className="primary"
            disabled={!content}
            onClick={async () => {
              onError(null);
              setCopied(null);
              try {
                const sanitized = await api.sanitize(filename, content);
                setResult(sanitized);
                // Only a twin that passed the gate. A blocked sanitize returns
                // none, and clearing it here stops the diff screen comparing
                // against a twin from some earlier document.
                setTwin(sanitized.twin);
                onDone();
              } catch (e) {
                setResult(null);
                setTwin(null);
                onError(String(e));
              }
            }}
          >
            Sanitize
          </button>
        </div>
        <textarea value={content} onChange={(e) => setContent(e.target.value)} placeholder="Paste the document here…" />
      </div>

      {result && !result.verified && (
        <div className="panel">
          <div className="banner block">
            <strong>Export blocked.</strong> The twin still contains content that must not leave
            this machine, so it is not shown and cannot be copied.
          </div>
          {result.leaks.length > 0 && (
            <table>
              <thead><tr><th>Leaked term</th><th>Line</th><th>Column</th></tr></thead>
              <tbody>
                {result.leaks.map((l, i) => (
                  <tr key={i}>
                    <td className="mono error">{l.matched}</td>
                    <td className="muted">{l.line}</td>
                    <td className="muted">{l.column}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {result.blocking_secrets.map((s, i) => (
            <div key={i} className="small error">Unredacted {s.secret_type} on line {s.line}</div>
          ))}
        </div>
      )}

      {result?.verified && result.twin && (
        <div className="panel">
          <div className={`banner ${result.unreadable ? "warn" : "ok"}`}>
            {result.unreadable ? (
              <>
                <strong>Gate passed &mdash; but nothing was aliased.</strong>{" "}
                <span className="small">
                  The parser claimed this file and could not read it, so no structural
                  aliasing was applied and no check was possible. What is below is your own
                  source with at most a few prose substitutions. It passed the gate because a
                  file nothing could read contains no vault names <em>yet</em> &mdash; not
                  because it is safe to send.
                </span>
              </>
            ) : (
              <>
                <strong>Verified clean.</strong>{" "}
                <span className="small">
                  {result.applied} identities aliased, {result.secrets_redacted} secrets
                  redacted, {result.patterns_checked} patterns checked against the vault.
                </span>
              </>
            )}
          </div>

          <div className="row" style={{ marginBottom: 10 }}>
            <button
              className="primary"
              onClick={async () => {
                try {
                  setCopied(await api.copyVerifiedTwin(true));
                } catch (e) {
                  onError(String(e));
                }
              }}
            >
              Copy twin + prompt envelope
            </button>
            <button
              onClick={async () => {
                try {
                  setCopied(await api.copyVerifiedTwin(false));
                } catch (e) {
                  onError(String(e));
                }
              }}
            >
              Copy twin only
            </button>
            <button
              onClick={async () => {
                onError(null);
                try {
                  // The twin is read from session state on the Rust side, never
                  // sent from here — same rule as the clipboard (SDD §17.5).
                  const saved = await api.saveVerifiedTwin(`${filename}.twin`);
                  if (saved) setSavedTo(saved);
                } catch (e) {
                  onError(String(e));
                }
              }}
            >
              Save twin…
            </button>
            {copied !== null && (
              <span className="small muted">
                {copied} characters copied — cleared from the clipboard after 2 minutes
              </span>
            )}
            {savedTo && <span className="small muted mono">saved to {savedTo}</span>}
          </div>

          <details>
            <summary className="small muted">What was <em>not</em> checked</summary>
            <ul className="small muted">
              {result.not_checked.map((n, i) => <li key={i}>{n}</li>)}
            </ul>
            <p className="small muted">
              SpecShield removes names, not meaning. A verified twin is safer to share —
              it is not non-confidential.
            </p>
          </details>

          <h4>Twin</h4>
          <textarea readOnly value={result.twin} />
        </div>
      )}
    </>
  );
}

function RestorePanel({ onError }: { onError: (e: string | null) => void }) {
  const [content, setContent] = useState("");
  const [result, setResult] = useState<RestoreResult | null>(null);

  return (
    <>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Restore</h3>
        <p className="muted small">
          Paste the model's response — a whole file, a fragment, a diff, or prose with code
          in it. Restoration is lexical, so none of those need to parse.
        </p>
        <textarea value={content} onChange={(e) => setContent(e.target.value)} placeholder="Paste the response here…" />
        <div className="row" style={{ marginTop: 10 }}>
          <button
            className="primary"
            disabled={!content}
            onClick={async () => {
              onError(null);
              try {
                setResult(await api.restore(content));
              } catch (e) {
                setResult(null);
                onError(String(e));
              }
            }}
          >
            Restore
          </button>
        </div>
      </div>

      {result && (
        <div className="panel">
          <div className="row small muted" style={{ marginBottom: 10 }}>
            <span>{result.restored.length} aliases restored</span>
            {result.redactions_preserved > 0 && (
              <span>· {result.redactions_preserved} redaction markers left in place</span>
            )}
          </div>

          {result.restored.some((r) => r.needs_review) && (
            <div className="banner warn">
              <strong>Review these.</strong> The model changed the token; it was matched by
              normalization rather than exactly.
              <table style={{ marginTop: 8 }}>
                <thead><tr><th>Found</th><th>Restored to</th><th>How</th><th>Line</th></tr></thead>
                <tbody>
                  {result.restored.filter((r) => r.needs_review).map((r, i) => (
                    <tr key={i}>
                      <td className="mono">{r.found}</td>
                      <td className="mono">{r.real_name}</td>
                      <td className="muted">{r.match_kind}</td>
                      <td className="muted">{r.line}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.unresolved.length > 0 && (
            <div className="banner block">
              <strong>{result.unresolved.length} unresolved identities.</strong>
              <div className="small">
                Alias-shaped tokens with no match. They are left untouched — SpecShield
                never guesses a name into your repository. Name them before applying.
              </div>
              <div className="mono small" style={{ marginTop: 6 }}>{result.unresolved.join(", ")}</div>
            </div>
          )}

          <h4>Restored</h4>
          <textarea readOnly value={result.text} />
        </div>
      )}
    </>
  );
}

/**
 * Workflow B, as a screen — SDD §13 and §14.
 *
 * Three versions are compared and two of them belong to the model: the twin
 * that was sent and the twin that came back. What the user is asked to accept is
 * the third comparison — the file on disk against the restored output — because
 * that is what a patch would write.
 *
 * The panel refuses in the same places the engine does, and says the same thing.
 * Disabling a button is a courtesy; every guard here is re-checked in Rust.
 */
function DiffPanel({
  doc,
  twin,
  onError,
}: {
  doc: Doc;
  twin: string | null;
  onError: (e: string | null) => void;
}) {
  const [aiTwin, setAiTwin] = useState("");
  const [pastedTwin, setPastedTwin] = useState("");
  const [review, setReview] = useState<DiffReview | null>(null);
  const [status, setStatus] = useState<PatchStatus | null>(null);
  const [applied, setApplied] = useState<AppliedPatch | null>(null);
  const [branch, setBranch] = useState("specshield/restore");

  const sentTwin = twin ?? pastedTwin;

  const run = useCallback(async () => {
    onError(null);
    setApplied(null);
    try {
      setReview(await api.reviewDiff(doc.content, sentTwin, aiTwin));
      setStatus(await api.patchStatus(doc.filename));
    } catch (e) {
      setReview(null);
      onError(String(e));
    }
  }, [doc.content, doc.filename, sentTwin, aiTwin, onError]);

  // Why a patch cannot be offered, in the order the engine checks it.
  const refusal =
    review?.blocks_patch
      ? "Unresolved identities remain. Name them below — SpecShield never guesses a name into your repository."
      : status && !status.file_exists
        ? `${doc.filename} is not a file under the project root, so there is nothing to patch.`
        : status?.stale
          ? "This file has changed since it was indexed. A patch built from this twin could apply cleanly and silently revert those edits — re-sanitize first."
          : status && !status.git_available
            ? status.git_explain
            : null;

  return (
    <>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Diff &amp; apply</h3>
        <p className="muted small">
          Paste what the model returned. It is compared against the twin that was sent and
          against <span className="mono">{doc.filename}</span> as it stands on disk.
        </p>

        {!twin && (
          <div className="banner warn">
            <strong>No twin from this session.</strong>
            <div className="small" style={{ marginTop: 4 }}>
              Sanitize the document first, or paste the twin you sent below. Without it the
              model-side comparison cannot be shown — the restored diff still can.
            </div>
            <textarea
              style={{ marginTop: 8 }}
              value={pastedTwin}
              onChange={(e) => setPastedTwin(e.target.value)}
              placeholder="The twin you sent (optional)…"
            />
          </div>
        )}

        <textarea
          value={aiTwin}
          onChange={(e) => setAiTwin(e.target.value)}
          placeholder="Paste the model's response here…"
        />
        <div className="row" style={{ marginTop: 10 }}>
          <button className="primary" disabled={!aiTwin || !doc.content} onClick={run}>
            Review
          </button>
          {!doc.content && (
            <span className="muted small">Load the original document on the Review step first.</span>
          )}
        </div>
      </div>

      {review && (
        <div className="panel">
          <div className="row small muted" style={{ marginBottom: 10 }}>
            <span>{review.changes.length} change(s)</span>
            <span>· {review.substantive} substantive</span>
            <span>· {review.model_changes} model-side edit(s)</span>
          </div>

          {review.changes.length === 0 && (
            <div className="banner ok">
              <strong>No changes.</strong> The restored output is identical to the file on disk.
            </div>
          )}

          {review.changes.map((hunk, i) => (
            <div key={i} className="hunk">
              <div className="hunk-head mono small">
                @@ −{hunk.before_start} +{hunk.after_start} @@{" "}
                <span className={hunk.kind === "formatting" ? "muted" : ""}>
                  {hunk.kind === "formatting" ? "formatting only" : hunk.kind}
                </span>
              </div>
              <pre className="mono small diff">
                {hunk.lines.map((line, j) => (
                  <div key={j} className={line.added ? "add" : "del"}>
                    {line.added ? "+" : "−"}
                    {line.text.replace(/\n$/, "")}
                  </div>
                ))}
              </pre>
              {hunk.notes.map((note, j) => (
                <div key={j} className={`note ${note.kind}`}>
                  {note.detail}
                </div>
              ))}
            </div>
          ))}

          {review.notes.length > 0 && (
            <>
              <h4>Everything worth checking</h4>
              <p className="muted small">
                Including anything that changed nothing visible — a loose match can restore to
                exactly the original text, and the guess still wrote a real name.
              </p>
              <table>
                <thead>
                  <tr><th>Line</th><th>Kind</th><th>Detail</th></tr>
                </thead>
                <tbody>
                  {review.notes.map((note, i) => (
                    <tr key={i}>
                      <td className="muted">{note.line}</td>
                      <td className={note.kind === "unresolved" ? "error" : "muted"}>{note.kind}</td>
                      <td className="small">{note.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      {review && review.unresolved.length > 0 && (
        <UnresolvedPanel tokens={review.unresolved} onError={onError} onResolved={run} />
      )}

      {review && (
        <div className="panel">
          <h4 style={{ marginTop: 0 }}>Apply</h4>

          {refusal ? (
            <div className="banner block">
              <strong>Cannot apply.</strong>
              <div className="small" style={{ marginTop: 4 }}>{refusal}</div>
            </div>
          ) : (
            <>
              <div className="row small muted" style={{ marginBottom: 10 }}>
                <span>on branch <span className="mono">{status?.branch}</span></span>
                {status?.dirty && <span>· working tree has uncommitted changes</span>}
                {status?.not_indexed && <span>· no checksum on file for this path</span>}
              </div>
              {status?.dirty && (
                <div className="banner warn small">
                  Undo reverses this patch and will fail if your own edits overlap it. Commit
                  first if you want a clean undo.
                </div>
              )}
              <div className="row">
                <input
                  className="grow mono"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                />
                <button
                  className="primary"
                  onClick={async () => {
                    onError(null);
                    try {
                      setApplied(await api.applyPatch(doc.filename, review.restored, branch));
                      setStatus(await api.patchStatus(doc.filename));
                    } catch (e) {
                      onError(String(e));
                    }
                  }}
                >
                  Apply to branch
                </button>
              </div>
              <p className="muted small" style={{ marginTop: 8 }}>
                Never applied to main, master, develop, or trunk. The patch is dry-run first,
                so a patch that would not apply changes nothing.
              </p>
            </>
          )}

          {applied && (
            <div className="banner ok" style={{ marginTop: 12 }}>
              <strong>Applied to {applied.branch}.</strong>
              <div className="small" style={{ marginTop: 4 }}>
                {applied.created_branch
                  ? `Branch created; you were on ${applied.previous_branch}.`
                  : `Already on ${applied.branch}.`}{" "}
                Review with <span className="mono">git diff</span>, then commit normally.
              </div>
              <button
                style={{ marginTop: 8 }}
                onClick={async () => {
                  onError(null);
                  try {
                    const now = await api.undoPatch();
                    setApplied(null);
                    onError(null);
                    setStatus(await api.patchStatus(doc.filename));
                    alert(`Reversed. You are on ${now}.`);
                  } catch (e) {
                    onError(String(e));
                  }
                }}
              >
                Undo
              </button>
            </div>
          )}
        </div>
      )}
    </>
  );
}

/**
 * SDD §12 — the user names entities the model invented.
 *
 * No suggestion is offered and no default is filled in. A plausible-looking
 * guess is how a wrong identifier gets committed to a real repository.
 */
function UnresolvedPanel({
  tokens,
  onError,
  onResolved,
}: {
  tokens: string[];
  onError: (e: string | null) => void;
  onResolved: () => void;
}) {
  const [names, setNames] = useState<Record<string, string>>({});
  const [types, setTypes] = useState<Record<string, EntityType>>({});

  return (
    <div className="panel">
      <div className="banner block">
        <strong>{tokens.length} unresolved identit(ies).</strong>
        <div className="small" style={{ marginTop: 4 }}>
          The model used alias-shaped tokens this project never issued. They stay in the
          restored text, and block applying, until you name them.
        </div>
      </div>

      <table>
        <thead>
          <tr><th>Alias</th><th>Real name</th><th>Type</th><th /></tr>
        </thead>
        <tbody>
          {tokens.map((token) => (
            <tr key={token}>
              <td className="mono">{token}</td>
              <td>
                <input
                  value={names[token] ?? ""}
                  placeholder="you supply this"
                  onChange={(e) => setNames({ ...names, [token]: e.target.value })}
                />
              </td>
              <td>
                <select
                  value={types[token] ?? "SERVICE"}
                  onChange={(e) => setTypes({ ...types, [token]: e.target.value as EntityType })}
                >
                  {ENTITY_TYPES.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </td>
              <td>
                <button
                  disabled={!names[token]}
                  onClick={async () => {
                    onError(null);
                    try {
                      await api.resolveIdentity(
                        token,
                        names[token] ?? "",
                        types[token] ?? "SERVICE",
                        "project",
                      );
                      onResolved();
                    } catch (e) {
                      onError(String(e));
                    }
                  }}
                >
                  Name it
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The local audit log — PRD FR-9.
 *
 * This is the artifact a security team asks for, and until now it existed only
 * on the command line: the log was being written on every operation with no way
 * to read it in the product people were actually shown.
 *
 * What it records is deliberately thin — that an operation happened, and its
 * shape. No names, no content, ever. That is what makes it safe to keep, safe to
 * export, and readable even when the vault itself will not open.
 */
function AuditPanel({ onError }: { onError: (e: string | null) => void }) {
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  const [limit, setLimit] = useState(100);
  const [saved, setSaved] = useState<string | null>(null);

  const load = useCallback(
    async (n: number) => {
      onError(null);
      setSaved(null);
      try {
        setRows(await api.auditLog(n));
      } catch (e) {
        setRows(null);
        onError(String(e));
      }
    },
    [onError],
  );

  useEffect(() => {
    void load(limit);
  }, [load, limit]);

  return (
    <>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Audit log</h3>
        <p className="muted small">
          Append-only, local, never transmitted. It records that an operation happened —
          never a real name and never any of your content. This is not telemetry; the
          product has none.
        </p>

        <div className="row">
          <label className="small muted">Show</label>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {[50, 100, 500, 2000].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <button onClick={() => void load(limit)}>Refresh</button>
          <button
            onClick={async () => {
              onError(null);
              try {
                setSaved(await api.exportAuditCsv(limit));
              } catch (e) {
                onError(String(e));
              }
            }}
          >
            Export CSV
          </button>
          <button
            onClick={async () => {
              onError(null);
              try {
                const csv = auditCsv(rows ?? []);
                const path = await api.saveText("specshield-audit.csv", csv);
                if (path) setSaved(path);
              } catch (e) {
                onError(String(e));
              }
            }}
          >
            Save as…
          </button>
          <span className="grow" />
          {rows && <span className="small muted">{rows.length} entries</span>}
        </div>

        {saved && (
          <div className="banner ok" style={{ marginTop: 10 }}>
            <strong>Written.</strong>
            <div className="small mono" style={{ marginTop: 4 }}>{saved}</div>
          </div>
        )}
      </div>

      {rows && rows.length === 0 && (
        <div className="panel">
          <p className="muted">Nothing recorded yet.</p>
        </div>
      )}

      {rows && rows.length > 0 && (
        <div className="panel">
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Operation</th>
                  <th>Files</th>
                  <th>Entities</th>
                  <th>Result</th>
                  <th>Destination</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, i) => (
                  <tr key={i}>
                    <td className="muted small">{formatTimestamp(row.ts)}</td>
                    <td className="mono">{row.operation}</td>
                    <td className="muted">{row.file_count ?? "—"}</td>
                    <td className="muted">{row.entity_count ?? "—"}</td>
                    <td className={row.verification === "blocked" ? "error" : "muted"}>
                      {row.verification ?? "—"}
                    </td>
                    <td className="muted small">{row.destination ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

/** Unix seconds as the local machine reads them. The log stores UTC seconds. */
function formatTimestamp(ts: number): string {
  const d = new Date(ts * 1000);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

/**
 * Vault operations — PRD FR-11 and SDD §16.
 *
 * Backup, escrow, re-key, and recovery. These make a lost or over-shared vault
 * survivable, and they lived only on the command line — out of reach of exactly
 * the people least likely to open a terminal.
 *
 * Two of the four are destructive in ways that cannot be undone, so both are
 * behind an explicit confirmation that states the consequence in full rather
 * than asking "are you sure?".
 */
function VaultPanel({ onError, onRekeyed }: { onError: (e: string | null) => void; onRekeyed: () => void }) {
  return (
    <>
      <BackupSection onError={onError} />
      <EscrowSection onError={onError} />
      <RekeySection onError={onError} onRekeyed={onRekeyed} />
      <RecoverySection onError={onError} />
    </>
  );
}

function BackupSection({ onError }: { onError: (e: string | null) => void }) {
  const [dest, setDest] = useState("../project.vault.backup");
  const [backup, setBackup] = useState("../project.vault.backup");
  const [into, setInto] = useState("../restored/.specshield/vault.bin");
  const [passphrase, setPassphrase] = useState("");
  const [done, setDone] = useState<string | null>(null);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Backup</h3>
      <p className="muted small">
        A consistent copy, encrypted exactly as the vault is and opened by the same
        passphrase. It is not a second factor: whoever has this file and the passphrase
        has the whole mapping. Relative paths are resolved against the project folder.
      </p>

      <div className="row">
        <PathField value={dest} onChange={setDest} onError={onError} />
        <button
          className="primary"
          onClick={async () => {
            onError(null);
            try {
              setDone(`Backed up to ${await api.backupVault(dest)}`);
            } catch (e) {
              onError(String(e));
            }
          }}
        >
          Back up
        </button>
      </div>

      <h4>Restore a backup</h4>
      <p className="muted small">
        Never writes over an existing vault, and proves the backup opens before the
        destination exists — a backup nobody can open is a failure discovered in the
        middle of the incident it existed for.
      </p>
      <div className="row">
        <PathField value={backup} onChange={setBackup} placeholder="backup file" onError={onError} />
        <PathField value={into} onChange={setInto} placeholder="destination" onError={onError} />
      </div>
      <div className="row" style={{ marginTop: 8 }}>
        <input
          className="grow"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="the backup's passphrase"
        />
        <button
          disabled={!passphrase}
          onClick={async () => {
            onError(null);
            try {
              setDone(`Restored to ${await api.restoreVault(backup, into, passphrase)}`);
            } catch (e) {
              onError(String(e));
            }
          }}
        >
          Restore
        </button>
      </div>

      {done && (
        <div className="banner ok" style={{ marginTop: 10 }}>
          <div className="small mono">{done}</div>
        </div>
      )}
    </div>
  );
}

function EscrowSection({ onError }: { onError: (e: string | null) => void }) {
  const [out, setOut] = useState("../project.escrow");
  const [escrowPassphrase, setEscrowPassphrase] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [warning, setWarning] = useState("");
  const [written, setWritten] = useState<string | null>(null);

  const [openFile, setOpenFile] = useState("../project.escrow");
  const [openWith, setOpenWith] = useState("");
  const [recovered, setRecovered] = useState<string | null>(null);

  useEffect(() => {
    void api.escrowWarning().then(setWarning).catch(() => setWarning(""));
  }, []);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Key escrow</h3>
      <p className="muted small">
        Seals this vault's passphrase under a second, separate one. Give the file to
        whoever holds recovery responsibility — they can get back in without knowing your
        passphrase. That also means they can get <em>all</em> the way in: there is no
        partial access, and an escrow file cannot be revoked once issued.
      </p>

      <div className="row">
        <PathField value={out} onChange={setOut} onError={onError} />
      </div>
      <div className="row" style={{ marginTop: 8 }}>
        <input
          className="grow"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="this vault's passphrase"
        />
        <input
          className="grow"
          type="password"
          value={escrowPassphrase}
          onChange={(e) => setEscrowPassphrase(e.target.value)}
          placeholder="the escrow passphrase (different)"
        />
        <button
          className="primary"
          disabled={!passphrase || !escrowPassphrase}
          onClick={async () => {
            onError(null);
            try {
              setWritten(await api.exportEscrow(out, escrowPassphrase, passphrase));
            } catch (e) {
              onError(String(e));
            }
          }}
        >
          Export
        </button>
      </div>

      {written && (
        <div className="banner warn" style={{ marginTop: 10 }}>
          <strong>Written to {written}</strong>
          <pre className="small mono" style={{ whiteSpace: "pre-wrap", marginTop: 8 }}>
            {warning}
          </pre>
        </div>
      )}

      <h4>Recover a passphrase from an escrow file</h4>
      <div className="row">
        <PathField value={openFile} onChange={setOpenFile} onError={onError} />
        <input
          className="grow"
          type="password"
          value={openWith}
          onChange={(e) => setOpenWith(e.target.value)}
          placeholder="the escrow passphrase"
        />
        <button
          disabled={!openWith}
          onClick={async () => {
            onError(null);
            try {
              setRecovered(await api.openEscrow(openFile, openWith));
            } catch (e) {
              setRecovered(null);
              onError(String(e));
            }
          }}
        >
          Recover
        </button>
      </div>

      {recovered && (
        <div className="banner block" style={{ marginTop: 10 }}>
          <strong>Treat this as the passphrase itself.</strong>
          <div className="mono" style={{ marginTop: 6 }}>{recovered}</div>
        </div>
      )}
    </div>
  );
}

function RekeySection({ onError, onRekeyed }: { onError: (e: string | null) => void; onRekeyed: () => void }) {
  const [count, setCount] = useState<number | null>(null);
  const [armed, setArmed] = useState(false);
  const [result, setResult] = useState<number | null>(null);

  useEffect(() => {
    void api
      .rekeyPreview()
      .then((p) => setCount(p.identities))
      .catch(() => setCount(null));
  }, [result]);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Re-key</h3>

      <div className="banner block">
        <strong>Re-keying changes every alias in this project.</strong>
        <div className="small" style={{ marginTop: 4 }}>
          {count === null ? "" : `All ${count} of them. `}
          Every twin you have already shared becomes unrestorable — its aliases will no
          longer resolve to anything. Do this when a twin has been over-shared, or when
          the alias style changes. Not otherwise.
          <br />
          <br />
          It does nothing to submissions already made: those twins sit in the provider's
          logs exactly as sent. What changes is that they no longer connect to anything
          you produce from now on.
          <br />
          <br />
          <strong>Back up first.</strong>
        </div>
      </div>

      <div className="row">
        <label className="small">
          <input type="checkbox" checked={armed} onChange={(e) => setArmed(e.target.checked)} />{" "}
          I have a backup and I understand every shared twin stops working
        </label>
        <span className="grow" />
        <button
          disabled={!armed}
          onClick={async () => {
            onError(null);
            try {
              setResult(await api.rekeyProject(true));
              setArmed(false);
              onRekeyed();
            } catch (e) {
              onError(String(e));
            }
          }}
        >
          Re-key
        </button>
      </div>

      {result !== null && (
        <div className="banner ok" style={{ marginTop: 10 }}>
          <strong>{result} alias(es) changed.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            Re-sanitize and re-send anything still in flight with a model.
          </div>
        </div>
      )}
    </div>
  );
}

function RecoverySection({ onError }: { onError: (e: string | null) => void }) {
  const [path, setPath] = useState("");
  const [report, setReport] = useState<RecoveryReport | null>(null);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Recovery</h3>
      <p className="muted small">
        For a vault that will not open. Needs no passphrase, reveals no real name, and
        cannot modify the file it is inspecting — it reports what the vault holds and what
        is wrong with it. Give the full path to a <span className="mono">vault.bin</span>.
      </p>

      <div className="row">
        <input
          className="grow mono"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="C:\\work\\billing\\.specshield\\vault.bin"
        />
        <button
          disabled={!path}
          onClick={async () => {
            onError(null);
            try {
              setReport(await api.recoverVault(path));
            } catch (e) {
              setReport(null);
              onError(String(e));
            }
          }}
        >
          Inspect
        </button>
      </div>

      {report && (
        <>
          <div className={`banner ${report.readable ? "warn" : "block"}`} style={{ marginTop: 10 }}>
            <strong>Diagnosis</strong>
            <div className="small" style={{ marginTop: 4 }}>{report.diagnosis}</div>
          </div>

          {report.readable && (
            <>
              <div className="row small muted">
                <span>schema v{report.schema_version}</span>
                <span>· {report.identities} identities</span>
                <span>· {report.files} indexed files</span>
              </div>

              {report.entity_types.length > 0 && (
                <table style={{ marginTop: 10 }}>
                  <thead><tr><th>Type</th><th>Count</th></tr></thead>
                  <tbody>
                    {report.entity_types.map(([kind, n]) => (
                      <tr key={kind}>
                        <td className="mono">{kind}</td>
                        <td className="muted">{n}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {report.audit.length > 0 && (
                <>
                  <h4>Last operations</h4>
                  <div className="scroll">
                    <table>
                      <tbody>
                        {report.audit.map((row, i) => (
                          <tr key={i}>
                            <td className="muted small">{formatTimestamp(row.ts)}</td>
                            <td className="mono">{row.operation}</td>
                            <td className="muted">{row.verification ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Whole-project operations — Workflow B's first half, and the pieces that were
 * command-line only.
 *
 * Index and rescan, twin export, cross-artifact unification, and a standalone
 * gate. All of it runs the same `specshield-project` pipeline the CLI runs;
 * this screen only decides how to say what happened.
 */
function ProjectOpsPanel({ onError, onChanged }: { onError: (e: string | null) => void; onChanged: () => void }) {
  return (
    <>
      <IndexSection onError={onError} />
      <ExportSection onError={onError} onChanged={onChanged} />
      <UnifySection onError={onError} onChanged={onChanged} />
      <WhereSection onError={onError} />
      <SecretsSection onError={onError} />
      <VerifySection onError={onError} />
    </>
  );
}

function IndexSection({ onError }: { onError: (e: string | null) => void }) {
  const [indexed, setIndexed] = useState<IndexSummary | null>(null);
  const [rescan, setRescan] = useState<RescanSummary | null>(null);
  const [busy, setBusy] = useState(false);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Index</h3>
      <p className="muted small">
        Walks the project, hashes every file, and records the checksums. Respects{" "}
        <span className="mono">.gitignore</span> and{" "}
        <span className="mono">.specshieldignore</span>. The checksums are what
        later tell you a twin was made from content that no longer exists.
      </p>

      <div className="row">
        <button
          className="primary"
          disabled={busy}
          onClick={async () => {
            onError(null);
            setBusy(true);
            setRescan(null);
            try {
              setIndexed(await api.indexProject());
            } catch (e) {
              onError(String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          Index project
        </button>
        <button
          disabled={busy}
          onClick={async () => {
            onError(null);
            setBusy(true);
            try {
              setRescan(await api.rescanProject());
            } catch (e) {
              onError(String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          Rescan
        </button>
      </div>

      {indexed && (
        <div className="banner ok" style={{ marginTop: 10 }}>
          <strong>{indexed.files} file(s) in {indexed.seconds.toFixed(2)}s.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            {indexed.text} text, {indexed.parseable} with a parser in this build,{" "}
            {indexed.files - indexed.parseable} binary or unparseable.
          </div>
        </div>
      )}

      {rescan && (
        <div className={`banner ${rescan.stale.length > 0 ? "warn" : "ok"}`} style={{ marginTop: 10 }}>
          <strong>
            {rescan.added.length} added, {rescan.modified.length} modified,{" "}
            {rescan.removed.length} removed, {rescan.unchanged} unchanged.
          </strong>
          {rescan.stale.length === 0 ? (
            <div className="small" style={{ marginTop: 4 }}>
              No stale twins: every recorded checksum still matches the file on disk.
            </div>
          ) : (
            <div className="small" style={{ marginTop: 4 }}>
              {rescan.stale.length} file(s) have changed since their twin was made. A patch
              built from those twins would revert the intervening edits — re-sanitize first.
              <div className="mono" style={{ marginTop: 6 }}>
                {rescan.stale.slice(0, 20).join(", ")}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ExportSection({ onError, onChanged }: { onError: (e: string | null) => void; onChanged: () => void }) {
  const [dest, setDest] = useState("../project-twin");
  const [result, setResult] = useState<ExportSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [twinIn, setTwinIn] = useState("../project-twin");
  const [restoreTo, setRestoreTo] = useState("../project-restored");
  const [restored, setRestored] = useState<RestoredProject | null>(null);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Export a twin project</h3>
      <p className="muted small">
        Sanitizes every file into a new directory, filenames and directories included and
        consistent with the imports inside the files — so the twin still resolves as a
        project. Nothing is written unless <em>every</em> file passes the gate: a directory
        that is clean apart from one leak is not clean.
      </p>

      <div className="row">
        <PathField value={dest} onChange={setDest} onError={onError} />
        <button
          className="primary"
          disabled={busy}
          onClick={async () => {
            onError(null);
            setBusy(true);
            try {
              setResult(await api.exportProject(dest));
              onChanged();
            } catch (e) {
              setResult(null);
              onError(String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Working…" : "Export"}
        </button>
      </div>

      {result && result.blocked.length > 0 && (
        <div className="banner block" style={{ marginTop: 10 }}>
          <strong>Export blocked — nothing was written.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            {result.blocked.length} file(s) did not verify.
          </div>
          <div className="scroll" style={{ marginTop: 8 }}>
            <table>
              <tbody>
                {result.blocked.map(([path, leaks]) => (
                  <tr key={path}>
                    <td className="mono small">{path}</td>
                    <td className="small error">{leaks.slice(0, 3).join("; ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <h4>Restore a twin project</h4>
      <p className="muted small">
        The inverse: every file back at its real path. Only reversible because the vault
        recorded the mapping when the twin was exported.
      </p>
      <div className="row">
        <PathField value={twinIn} onChange={setTwinIn} placeholder="the twin directory" onError={onError} />
        <PathField
          value={restoreTo}
          onChange={setRestoreTo}
          placeholder="where to put it back"
          onError={onError}
        />
        <button
          disabled={busy}
          onClick={async () => {
            onError(null);
            setBusy(true);
            try {
              setRestored(await api.restoreProject(twinIn, restoreTo));
            } catch (e) {
              setRestored(null);
              onError(String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          Restore project
        </button>
      </div>

      {restored && (
        <div className="banner ok" style={{ marginTop: 10 }}>
          <strong>
            {restored.written} file(s) into {restored.destination}.
          </strong>
          <div className="small" style={{ marginTop: 4 }}>
            {restored.aliases_resolved} alias occurrence(s) resolved.{" "}
            {restored.unmapped.length === 0
              ? "Every twin path mapped back to a real path."
              : `${restored.unmapped.length} file(s) had no path mapping and were left where they stand.`}
          </div>
        </div>
      )}

      {result && result.blocked.length === 0 && (
        <div className="banner ok" style={{ marginTop: 10 }}>
          <strong>{result.written} file(s) written to {result.destination}.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            {result.aliased} alias applications, {result.identities} identities in the vault,{" "}
            {result.renamed} path(s) renamed. Every file passed the gate, paths included.
            <br />
            {result.allowlisted > 0 &&
              ` ${result.allowlisted} name(s) the gate was told to ignore.`}{" "}
            {result.unchecked} file(s) had no structure to verify against.
            {result.abandoned.length === 0
              ? " Every parsed file verified structurally."
              : ` ${result.abandoned.length} file(s) exported UNALIASED — aliasing was abandoned.`}
            <br />
            {result.occurrences} occurrence(s) recorded, searchable under &ldquo;Where is
            it&rdquo;.
          </div>
          {result.unreadable.length > 0 && (
            <div className="small" style={{ marginTop: 6 }}>
              <strong>
                {result.unreadable.length} file(s) went out UNALIASED &mdash; a parser
                claimed them and could not read them.
              </strong>
              <div className="mono small" style={{ marginTop: 6 }}>
                {result.unreadable.map(([path, why]) => path + ": " + why).join("\n")}
              </div>
            </div>
          )}
          {result.redacted > 0 && (
            <div className="small" style={{ marginTop: 6 }}>
              <strong>
                {result.redacted} secret(s) redacted, {result.redacted_new} not seen before.
              </strong>{" "}
              The twin is clean. Those credentials are still in your working tree &mdash;
              this export did nothing about that. &ldquo;Secrets found&rdquo; below lists
              where.
            </div>
          )}
          {result.abandoned.length > 0 && (
            <div className="mono small" style={{ marginTop: 6 }}>
              {result.abandoned.map(([path, why]) => `${path}: ${why}`).join("\n")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function position(line: number, column: number): string {
  // Zero means the offset could not be resolved against the file as it stands —
  // it changed, or it is gone. Showing ":0:0" would look like a real position.
  return line === 0 ? "" : `:${line}:${column}`;
}

function WhereSection({ onError }: { onError: (e: string | null) => void }) {
  const [name, setName] = useState("");
  const [found, setFound] = useState<LocatedIdentity[] | null>(null);
  const [busy, setBusy] = useState(false);

  const search = async () => {
    if (name.trim() === "") return;
    onError(null);
    setBusy(true);
    try {
      setFound(await api.locateIdentity(name.trim()));
    } catch (e) {
      setFound(null);
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Where is it</h3>
      <p className="muted small">
        Both directions of the same question. Type a real name to find every place the
        project uses it, or paste an alias out of a model&rsquo;s reply to find out what it
        was and where it came from. Real names match ignoring case; aliases must match
        exactly, because an alias is issued rather than remembered.
      </p>

      <div className="row">
        <input
          value={name}
          placeholder="CustomerService, or SERVICE_H7K2Q3"
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void search();
          }}
        />
        <button className="primary" disabled={busy || name.trim() === ""} onClick={() => void search()}>
          {busy ? "Looking…" : "Find"}
        </button>
      </div>

      {found !== null && found.length === 0 && (
        <div className="banner warn" style={{ marginTop: 10 }}>
          <strong>No identity by that name.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            Nothing in the vault matches. A name the project has never been scanned for is
            not in here yet.
          </div>
        </div>
      )}

      {found?.map((identity) => (
        <div key={identity.alias} className="banner ok" style={{ marginTop: 10 }}>
          <strong className="mono">{identity.alias}</strong>{" "}
          <span className="small">
            {identity.entity_type} &middot; {identity.real_name}
          </span>
          <div className="muted small" style={{ marginTop: 4 }}>
            scope: <span className="mono">{identity.scope_path}</span>
          </div>

          {identity.appearances.length === 0 ? (
            <div className="small" style={{ marginTop: 6 }}>
              No recorded occurrences. They are written by an export, so a project that has
              only been scanned has none &mdash; which is not the same as appearing nowhere.
            </div>
          ) : (
            <div className="scroll" style={{ marginTop: 8 }}>
              <table>
                <tbody>
                  {identity.appearances.slice(0, 200).map((a, i) => (
                    <tr key={`${a.path}-${a.line}-${a.column}-${i}`}>
                      <td className="mono small">
                        {a.path}
                        {position(a.line, a.column)}
                      </td>
                      <td className="small muted">{a.kind}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function SecretsSection({ onError }: { onError: (e: string | null) => void }) {
  const [sites, setSites] = useState<SecretSite[] | null>(null);
  const [busy, setBusy] = useState(false);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Secrets found</h3>
      <p className="muted small">
        What the last export redacted out of the twin, and where each one still sits in your
        working tree. Positions only &mdash; the vault keeps a one-way index and no
        plaintext, so it can tell you where it found something and never what.
      </p>

      <div className="row">
        <button
          disabled={busy}
          onClick={async () => {
            onError(null);
            setBusy(true);
            try {
              setSites(await api.secretSites());
            } catch (e) {
              setSites(null);
              onError(String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Reading…" : "Show secrets"}
        </button>
      </div>

      {sites !== null && sites.length === 0 && (
        <div className="banner ok" style={{ marginTop: 10 }}>
          <strong>Nothing on record.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            Recorded by an export. A project that has not been exported has none on record,
            which is not the same as having none.
          </div>
        </div>
      )}

      {sites !== null && sites.length > 0 && (
        <div className="banner warn" style={{ marginTop: 10 }}>
          <strong>{sites.length} secret(s) redacted out of the twin.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            These are live credentials in your own files. Sanitizing them out of the twin
            protected the model&rsquo;s copy and nothing else.
          </div>
          <div className="scroll" style={{ marginTop: 8 }}>
            <table>
              <tbody>
                {sites.slice(0, 200).map((s, i) => (
                  <tr key={`${s.path}-${s.line}-${i}`}>
                    <td className="mono small">
                      {s.path}
                      {position(s.line, s.column)}
                    </td>
                    <td className="small">{s.secret_type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function UnifySection({ onError, onChanged }: { onError: (e: string | null) => void; onChanged: () => void }) {
  const [proposals, setProposals] = useState<UnifyProposal[] | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);

  const load = useCallback(async () => {
    onError(null);
    try {
      setProposals(await api.unifyProposals());
    } catch (e) {
      setProposals(null);
      onError(String(e));
    }
  }, [onError]);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Cross-artifact concepts</h3>
      <p className="muted small">
        The SQL table, the OpenAPI schema, and the TypeScript DTO can be one thing seen
        from three sides. Confirming a concept gives them a shared alias suffix with
        different prefixes, so a model sees the connection while restore stays
        unambiguous.
      </p>
      <p className="muted small">
        <strong>Nothing is unified without confirmation.</strong> A name match is not
        evidence — three unrelated <span className="mono">Status</span> enums share a name
        and are three different things.
      </p>

      <div className="row">
        <button onClick={() => void load()}>Find proposals</button>
      </div>

      {proposals && proposals.length === 0 && (
        <p className="muted small" style={{ marginTop: 10 }}>
          No proposals. One needs a compatible pair of <em>different</em> kinds — a table
          and a DTO, a service and an API. Identities sharing a name and a kind are a
          collision, not a concept.
        </p>
      )}

      {proposals?.map((p) => (
        <div key={p.concept} className="hunk" style={{ marginTop: 10 }}>
          <div className="hunk-head small">
            <span className="mono">{p.concept}</span>{" "}
            <span className="muted">confidence {p.confidence.toFixed(2)}</span>
          </div>
          <table>
            <tbody>
              {p.members.map((m, i) => (
                <tr key={i}>
                  <td className="mono">{m.entity_type}</td>
                  <td className="mono">{m.real_name}</td>
                  <td className="muted small">{m.scope_path}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {p.caveat && <div className="note fuzzy">{p.caveat}</div>}
          <div className="row" style={{ padding: "8px 10px" }}>
            <button
              onClick={async () => {
                onError(null);
                try {
                  const [linked, changed] = await api.unifyConfirm(p.concept);
                  setOutcome(
                    `Linked ${linked} identities as "${p.concept}". ${changed} alias(es) re-derived.`,
                  );
                  onChanged();
                  await load();
                } catch (e) {
                  onError(String(e));
                }
              }}
            >
              Confirm
            </button>
          </div>
        </div>
      ))}

      {outcome && (
        <div className="banner warn" style={{ marginTop: 10 }}>
          <strong>{outcome}</strong>
          <div className="small" style={{ marginTop: 4 }}>
            Those aliases changed, so any twin already sent to a model is orphaned — its
            aliases no longer resolve. Re-sanitize before the next request.
          </div>
        </div>
      )}
    </div>
  );
}

function VerifySection({ onError }: { onError: (e: string | null) => void }) {
  const [content, setContent] = useState("");
  const [result, setResult] = useState<VerifyResult | null>(null);

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Check anything</h3>
      <p className="muted small">
        Runs the export gate over text that did not come from Sanitize — something edited
        by hand, or a fragment about to be pasted somewhere.
      </p>

      <textarea value={content} onChange={(e) => setContent(e.target.value)} placeholder="Paste anything…" />
      <div className="row" style={{ marginTop: 10 }}>
        <button
          disabled={!content}
          onClick={async () => {
            onError(null);
            try {
              setResult(await api.verifyText(content));
            } catch (e) {
              setResult(null);
              onError(String(e));
            }
          }}
        >
          Check
        </button>
      </div>

      {result && result.patterns_checked === 0 && (
        <div className="banner warn" style={{ marginTop: 10 }}>
          <strong>Nothing was checked.</strong>
          <div className="small" style={{ marginTop: 4 }}>
            This project has no identities yet, so the gate had nothing to look for. A
            dictionary term is not enough — a name is interned the first time it is
            aliased. Sanitize or export something first.
          </div>
        </div>
      )}

      {result && result.patterns_checked > 0 && (
        <div className={`banner ${result.clean ? "ok" : "block"}`} style={{ marginTop: 10 }}>
          <strong>
            {result.clean
              ? `Clean — ${result.patterns_checked} patterns checked.`
              : "Not clean."}
          </strong>
          {result.leaks.length > 0 && (
            <table style={{ marginTop: 8 }}>
              <thead><tr><th>Leaked</th><th>Line</th><th>Column</th></tr></thead>
              <tbody>
                {result.leaks.map((l, i) => (
                  <tr key={i}>
                    <td className="mono error">{l.matched}</td>
                    <td className="muted">{l.line}</td>
                    <td className="muted">{l.column}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {result.secrets.length > 0 && (
            <div className="small" style={{ marginTop: 6 }}>
              {result.secrets.length} secret(s) found:{" "}
              {result.secrets.map((s) => `${s.secret_type} (line ${s.line})`).join(", ")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The same CSV the Rust side writes, for "Save as…".
 *
 * Duplicated deliberately and kept trivial: the alternative is a command that
 * takes a path from the frontend and writes to it, which is the one thing the
 * picker design exists to avoid.
 */
function auditCsv(rows: AuditRow[]): string {
  const field = (v: string) => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  const lines = ["timestamp,operation,file_count,entity_count,verification,destination"];
  for (const r of rows) {
    lines.push(
      [
        String(r.ts),
        field(r.operation),
        r.file_count ?? "",
        r.entity_count ?? "",
        field(r.verification ?? ""),
        field(r.destination ?? ""),
      ].join(","),
    );
  }
  return `${lines.join("\n")}\n`;
}
