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
  type EntityType,
  type ProjectInfo,
  type RestoreResult,
  type SanitizeResult,
  type ScanResult,
} from "./api";

type Step = "project" | "review" | "verify" | "restore";

const ENTITY_TYPES: EntityType[] = [
  "ORG", "SERVICE", "API", "ENDPOINT", "DB_TABLE",
  "COLUMN", "DTO", "IFACE", "ENUM", "EVENT", "ENV", "HOST", "PATH",
];

/// The document under review, held once at the top so Review and Sanitize
/// operate on the same text. Keeping a copy per panel meant a user reviewed one
/// document and sanitized whatever they happened to paste next — which is
/// exactly the mistake this tool exists to prevent.
interface Doc {
  filename: string;
  content: string;
}

export function App() {
  const [project, setProject] = useState<ProjectInfo | null>(null);
  const [step, setStep] = useState<Step>("project");
  const [error, setError] = useState<string | null>(null);
  const [doc, setDoc] = useState<Doc>({ filename: "PRD.md", content: "" });

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
        {(["project", "review", "verify", "restore"] as Step[]).map((s, i) => (
          <button
            key={s}
            className={`step ${step === s ? "active" : ""}`}
            disabled={s !== "project" && !project}
            onClick={() => setStep(s)}
          >
            {i + 1}. {{ project: "Project", review: "Review", verify: "Sanitize & verify", restore: "Restore" }[s]}
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
        <SanitizePanel doc={doc} setDoc={setDoc} onError={setError} onDone={refresh} />
      )}
      {step === "restore" && project && <RestorePanel onError={setError} />}
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
          <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\\work\\billing" />
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
                        <td className="muted">{s.confidence.toFixed(2)}</td>
                        <td>
                          <button
                            onClick={async () => {
                              await api.addTerm(s.real_name, "ORG");
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
}: {
  doc: Doc;
  setDoc: (d: Doc) => void;
  onError: (e: string | null) => void;
  onDone: () => void;
}) {
  const { filename, content } = doc;
  const setFilename = (f: string) => setDoc({ ...doc, filename: f });
  const setContent = (c: string) => setDoc({ ...doc, content: c });
  const [result, setResult] = useState<SanitizeResult | null>(null);
  const [copied, setCopied] = useState<number | null>(null);

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
                setResult(await api.sanitize(filename, content));
                onDone();
              } catch (e) {
                setResult(null);
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
          <div className="banner ok">
            <strong>Verified clean.</strong>{" "}
            <span className="small">
              {result.applied} identities aliased, {result.secrets_redacted} secrets redacted,{" "}
              {result.patterns_checked} patterns checked against the vault.
            </span>
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
            {copied !== null && (
              <span className="small muted">
                {copied} characters copied — cleared from the clipboard after 2 minutes
              </span>
            )}
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
