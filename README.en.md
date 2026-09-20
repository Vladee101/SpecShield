<!-- [Русский](README.md) · English -->

# SpecShield

**Identity gateway for secure agentic software development.**

A local-first desktop application and CLI that let you use commercial language
models — ChatGPT, Codex, Claude Code, Gemini — on proprietary code and
documents. SpecShield replaces **business identity** with stable aliases, leaves
the **architecture** readable, and rewrites the model's answer back into your
real names.

```text
Acme Bank offers Gold Business Subscription.        ORG_001 offers PRODUCT_001.

BillingService stores the subscription in     ──▶   BillingService stores the subscription in
customer_subscription and charges Stripe.           customer_subscription and charges PAYMENT_PROVIDER_001.
```

Note what did **not** change. `BillingService` and `customer_subscription`
travel verbatim, and that is the product rather than an oversight: an agent that
cannot read your architecture cannot help you extend it. A twin in which
`CustomerSubscription` is `DTO_004` gives the model nothing to build on.

> **It removes names, not meaning.** The twin still says what your code does. If
> the *logic* or the *architecture* is your secret, do not send it to a
> commercial LLM, with or without this tool. Detail:
> [Residual Risk](docs/en/Residual%20Risk.md).

---

## What is hidden and what is kept

| | Examples | In the twin |
|---|---|---|
| **Identity** — who you are, who you work with, where you run | `Vantor`, `Gold Business Subscription`, `Stripe`, `Jane Okafor`, `api.vantor-freight.com` | **Replaced** |
| **Structure** — what you built | `BillingService`, `CustomerSubscription`, `customer_subscription`, `POST /subscriptions` | **Kept** |
| **Secrets** — keys, tokens, connection strings | `AKIA…`, `ghp_…`, `postgres://u:p@…` | **Redacted one-way**, never restored |

Nine identity categories: organization, product, brand, partner, payment
provider, person, tenant, environment, domain. Any structural name can be
promoted by name — `specshield term settlement_ledger --entity-type table`; none
is by default.

Some identity is found with no configuration at all: a built-in table of roughly
fifty commercial services (`Stripe`, `Twilio`, `Auth0`), a hostname-shape rule,
and person markers (`@author`, `Contact:`, `Reviewed-by:`). The rest — your
company, your products, your customers — is unguessable, and you name it once.

---

## Quick start

```bash
cargo build --release                      # binary at target/release/specshield
cd /path/to/your/project
export SPECSHIELD_PASSPHRASE='a long passphrase you will not lose'

specshield init .
specshield term "Acme Bank" --entity-type organization

specshield scan docs/prd.md                # what was found, changing nothing
specshield sanitize docs/prd.md --envelope # the twin plus the prompt preamble
# …send it to the model, bring the answer back…
specshield restore reply.md > restored.md
```

For a whole repository:

```bash
specshield index
specshield export ../project-twin          # a twin tree whose imports resolve
# …the agent works on ../project-twin…
specshield restore ../project-twin --out ../restored
specshield apply src/billing.ts --ai ../restored/src/billing.ts --branch feature/ai
```

The desktop application does the same things through a window:

```bash
cd app && npm install && npm run tauri dev
```

**Add `.specshield/` to your `.gitignore`.** It holds the mapping from every
alias back to a real name, and it is the most sensitive artifact the tool
produces.

---

## What is guaranteed, and what is not

Three properties are tested rather than claimed:

- **`restore(sanitize(x)) == x`, byte for byte.** Property-tested across the
  whole golden corpus.
- **The twin parses, and its structure matches the original.** If an edit would
  break a file, aliasing is abandoned and the file goes through unaliased — and
  is reported, rather than emitted broken.
- **Nothing reaches a network.** The application has no HTTP client and no
  network permission; the entire Tauri permission list is three entries, and a
  test pins it to exactly those three. CI runs the whole suite inside a network
  namespace with no route out.

What is **not** guaranteed, plainly: business logic, algorithms and the shape of
the architecture reach the model in full; a distinctive domain model can
re-identify the organization with every name replaced; a name you never entered
in the dictionary is protected by nothing.

### Metrics

Measured in CI against a committed, hand-labelled corpus of seven synthetic
projects, on every commit.

| | Value | Target |
|---|---|---|
| Recall, rules only | **49.0%** | — |
| Recall, with dictionary | **100%** | ≥ 95% |
| Precision | **98.0%** | ≥ 90% |
| Secret detection | **6 / 6** | 100% |
| Tests | **439** | — |

Read the first row. "Rules only" is what the detector finds against an empty
vault — all a user has before they have typed anything. The dictionary column
mostly measures that seeding a dictionary works.

---

## Status

The engine works and is verified through the CLI. What is not ready:

- **Installers are unsigned** — SmartScreen and Gatekeeper will warn.
- **The desktop UI has not been driven end to end** through a running Tauri
  window; all end-to-end verification went through the CLI.
- **There is no OS credential store** — the passphrase is the only key path.
- **Alias durability through a real model API is unmeasured.**

Full list: [Residual Risk §3](docs/en/Residual%20Risk.md) and [`TODO.md`](TODO.md).

---

## Documentation

The Russian translation lives in [`docs/`](docs/README.md); the English
originals are in [`docs/en/`](docs/en/README.md) and are canonical.

| Document | For |
|---|---|
| [Complete Reference](docs/en/Complete%20Reference.md) | Every feature, every use case, and the guide in one place |
| [User Guide](docs/en/User%20Guide.md) | The command line, scripts, CI |
| [Desktop User Guide](docs/en/Desktop%20User%20Guide.md) | The application |
| [Security Review One-Pager](docs/en/Security%20Review%20One-Pager.md) | Ten minutes and a decision to make |
| [Threat Model](docs/en/Threat%20Model.md) | What is defended, where it is enforced, how to check |
| [Residual Risk](docs/en/Residual%20Risk.md) | What stays exposed. Deliberately the least flattering document here |

The specifications sit in the repository root:

- [`Product Requirements Document (PRD).md`](Product%20Requirements%20Document%20%28PRD%29.md)
  — requirements, what is protected §4, metrics §5, principles §7, aliases §13
- [`Software Design Document (SDD).md`](Software%20Design%20Document%20%28SDD%29.md)
  — architecture, alias grammar §6, verification §7–8, vault §9
- [`Implementation Plan.md`](Implementation%20Plan.md) — milestones and decisions
- [`TODO.md`](TODO.md) — what is done, what is not, and what is known wrong

---

## Layout

The engine is headless; the application and the CLI are drivers. Anything the
application can do, the CLI can do without a window.

```
crates/core/      model, aliases, edits, detection, secrets,
                  sanitization, restore, the export gate, diff
crates/parsers/   one parser per format: markdown, sql, openapi,
                  yaml, json, typescript, plantuml, text
crates/vault/     SQLite + per-value AES-256-GCM, Argon2id, blind index
crates/index/     tree walk, BLAKE3, ignore rules
crates/project/   the shared pipeline: index, export, restore, gate
crates/git/       patch generation and application
crates/cli/       the specshield binary
app/              desktop application, Tauri v2 + React
corpus/           the golden corpus: seven labelled synthetic projects
```

Rust 1.90+, edition 2024, `unsafe_code = "forbid"` across the workspace.

### Build and check

```bash
cargo build --release
cargo test --workspace                          # 439 tests
cargo clippy --workspace --all-targets
cargo run -p specshield-cli -- report corpus --strict
```

CI runs eight jobs: `fmt`, `clippy`, `test`, `docs`, `corpus`, `deny`, `perf`
and `offline` — the last runs the whole suite inside a network namespace with no
route out, after first asserting the namespace really has no DNS, because a test
that would pass with egress available proves nothing.

---

## Security

The vault is `.specshield/vault.bin`: SQLite with every sensitive value sealed
individually under AES-256-GCM with a random data key, which is itself wrapped
by a key derived from your passphrase with Argon2id. Each ciphertext is bound to
its table, column and row. Searchability comes from a blind index (HMAC), not
from decryption. Aliases are plaintext deliberately — they are what gets sent to
the model.

**The passphrase cannot be recovered.** Nothing about it is stored anywhere.
Make a backup and a key escrow on day one:

```bash
specshield backup ~/secure/project.vault.backup
specshield escrow ~/secure/project.escrow --escrow-passphrase '<second passphrase>'
```

If you find a security problem, start with the
[Threat Model](docs/en/Threat%20Model.md): it lists what is claimed, where it is
enforced, and what tests it. A claim that is not there is not a claim.

---

## License

`UNLICENSED`, with no license file — which by default means all rights reserved.
Settle this before making the repository public: with no license nobody may use
the code, even where they can read it.
