//! M0 spike — which alias format survives a model round trip?
//!
//! Freezes the SDD §6.3 grammar. The question splits cleanly in two:
//!
//! 1. **Recoverability** — *if* a model applies drift D to format F, can the
//!    restore matcher still resolve it? Fully determined by our own code, so it
//!    is computed here, offline, with no model involved.
//! 2. **Frequency** — how often does each drift actually occur? Requires real
//!    model calls; this binary emits the prompt pack for that run and scores
//!    the responses when they come back.
//!
//! Part 1 alone is decision-relevant: a format that is unrecoverable under
//! common drift is disqualified regardless of how rare the drift turns out to
//! be. Part 2 only ranks the survivors.
//!
//! Run: `cargo run -p spike-alias-roundtrip`
//!      `cargo run -p spike-alias-roundtrip -- --emit-prompts <dir>`

use std::collections::BTreeSet;

use anyhow::Result;
use specshield_core::alias::{canonical, is_alias_shaped};

// ---------------------------------------------------------------------------
// Candidate formats
// ---------------------------------------------------------------------------

struct Format {
    name: &'static str,
    sample: &'static str,
    note: &'static str,
}

const FORMATS: &[Format] = &[
    Format {
        name: "sequence",
        sample: "SERVICE_014",
        note: "the PRD v1.0 examples; needs a central allocator",
    },
    Format {
        name: "opaque-hmac",
        sample: "SERVICE_H7K2Q3",
        note: "implemented AliasStyle::Opaque",
    },
    Format {
        name: "typed-hmac",
        sample: "PrimaryService_H7K2Q3",
        note: "implemented AliasStyle::Typed (current default)",
    },
    Format {
        name: "delimiter-wrapped",
        sample: "__SERVICE_014__",
        note: "leading/trailing sentinels to discourage rewriting",
    },
    Format {
        name: "namespaced",
        sample: "SS_SERVICE_014",
        note: "product-prefixed to avoid collision with project constants",
    },
    Format {
        name: "pseudonymous",
        sample: "AuroraService",
        note: "implemented AliasStyle::Pseudonymous; reads as ordinary code",
    },
];

// ---------------------------------------------------------------------------
// Observed drift
// ---------------------------------------------------------------------------

struct Drift {
    name: &'static str,
    apply: fn(&str) -> String,
    severity: Severity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Severity {
    /// Seen routinely in model output.
    Common,
    /// Seen occasionally.
    Occasional,
}

fn to_pascal(s: &str) -> String {
    s.split(['_', '-'])
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut chars = p.chars();
            chars.next().map_or_else(String::new, |c| {
                c.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
            })
        })
        .collect()
}

const DRIFTS: &[Drift] = &[
    Drift {
        name: "verbatim",
        apply: |s| s.to_owned(),
        severity: Severity::Common,
    },
    Drift {
        name: "lowercased",
        apply: str::to_lowercase,
        severity: Severity::Common,
    },
    Drift {
        name: "PascalCased",
        apply: to_pascal,
        severity: Severity::Common,
    },
    Drift {
        name: "underscores stripped",
        apply: |s| s.replace('_', ""),
        severity: Severity::Common,
    },
    Drift {
        name: "hyphenated",
        apply: |s| s.replace('_', "-"),
        severity: Severity::Occasional,
    },
    Drift {
        name: "leading zeros dropped",
        apply: |s| s.replace("_0", "_"),
        severity: Severity::Occasional,
    },
    Drift {
        name: "pluralized",
        apply: |s| format!("{s}s"),
        severity: Severity::Occasional,
    },
    Drift {
        name: "backtick-wrapped",
        apply: |s| format!("`{s}`"),
        severity: Severity::Common,
    },
    Drift {
        name: "suffixed (Impl)",
        apply: |s| format!("{s}Impl"),
        severity: Severity::Occasional,
    },
    Drift {
        name: "word-split",
        apply: |s| s.replace('_', " "),
        severity: Severity::Occasional,
    },
];

/// Ordinary identifiers drawn from the corpus. A format that makes these look
/// like aliases will report every one as an unresolved identity.
const REAL_IDENTIFIERS: &[&str] = &[
    "MAX_RETRIES",
    "DEFAULT_TIMEOUT",
    "HTTP_OK",
    "API_BASE_URL",
    "AWS_ACCESS_KEY_ID",
    "PAYLANE_WEBHOOK_SECRET",
    "VANTOR_BILLING_URL",
    "CustomerSubscription",
    "customerId",
    "customer_id",
    "createSubscription",
    "PlanTier",
    "SubscriptionService",
];

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "--emit-prompts") {
        let dir = args.get(1).map_or("spikes/alias-roundtrip/prompts", String::as_str);
        emit_prompts(dir)?;
        return Ok(());
    }

    println!("# M0 spike — alias format round trip\n");
    println!("Part 1 of 2. Recoverability is computed offline; drift *frequency*");
    println!("needs real model calls (see `--emit-prompts`).\n");

    // -----------------------------------------------------------------
    // Recoverability matrix
    // -----------------------------------------------------------------
    println!("## Recoverability under drift\n");
    println!("Can `alias::canonical` still match the drifted token to the original?\n");

    print!("| Format | Sample |");
    for drift in DRIFTS {
        print!(" {} |", drift.name);
    }
    println!();
    print!("|---|---|");
    for _ in DRIFTS {
        print!(":-:|");
    }
    println!();

    let mut scores: Vec<(&str, usize, usize, usize)> = Vec::new();

    for format in FORMATS {
        print!("| `{}` | `{}` |", format.name, format.sample);
        let want = canonical(format.sample);
        let mut recovered = 0;
        let mut common_recovered = 0;
        let mut common_total = 0;

        for drift in DRIFTS {
            let drifted = (drift.apply)(format.sample);
            let ok = canonical(&drifted) == want;
            if ok {
                recovered += 1;
            }
            if drift.severity == Severity::Common {
                common_total += 1;
                if ok {
                    common_recovered += 1;
                }
            }
            print!(" {} |", if ok { "y" } else { "**n**" });
        }
        println!();
        scores.push((format.name, recovered, common_recovered, common_total));
    }

    println!("\n### Summary\n");
    println!("| Format | Recovered | Under common drift |");
    println!("|---|---:|---:|");
    for (name, recovered, common_recovered, common_total) in &scores {
        println!(
            "| `{name}` | {recovered}/{} | {common_recovered}/{common_total} |",
            DRIFTS.len()
        );
    }

    // -----------------------------------------------------------------
    // False-positive risk
    // -----------------------------------------------------------------
    println!("\n## False-positive risk\n");
    println!("Ordinary identifiers that the matcher would treat as alias-shaped,");
    println!("and therefore report as unresolved identities:\n");

    let flagged: Vec<&str> = REAL_IDENTIFIERS
        .iter()
        .copied()
        .filter(|id| is_alias_shaped(id))
        .collect();

    if flagged.is_empty() {
        println!(
            "None of the {} corpus identifiers are alias-shaped.\n",
            REAL_IDENTIFIERS.len()
        );
    } else {
        for id in &flagged {
            println!("- `{id}`");
        }
        println!();
    }

    // -----------------------------------------------------------------
    // Canonical collision check
    // -----------------------------------------------------------------
    println!("## Canonical collisions between formats\n");
    println!("Two distinct aliases sharing a canonical form would restore to the");
    println!("wrong identity — the one failure mode with no safe recovery.\n");

    let mut canon = BTreeSet::new();
    let mut collisions = Vec::new();
    for format in FORMATS {
        for drift in DRIFTS {
            let token = (drift.apply)(format.sample);
            let c = canonical(&token);
            if !canon.insert(c.clone()) {
                collisions.push((format.name, drift.name, c));
            }
        }
    }
    // Same-format drift collapsing onto the same canonical form is the point,
    // so only report collisions across *different* base samples.
    let cross: Vec<_> = collisions
        .iter()
        .filter(|(f, _, c)| {
            FORMATS
                .iter()
                .filter(|other| other.name != *f)
                .any(|other| canonical(other.sample) == *c)
        })
        .collect();

    if cross.is_empty() {
        println!("No cross-format canonical collisions.\n");
    } else {
        for (format, drift, c) in &cross {
            println!("- `{format}` under {drift} collides on `{c}`");
        }
        println!();
    }

    println!("## Notes\n");
    for format in FORMATS {
        println!("- `{}` — {}", format.name, format.note);
    }

    Ok(())
}

/// Write the prompt pack for part 2. Each file is a complete prompt: paste it
/// into a model, save the response beside it, then score with `--score`.
fn emit_prompts(dir: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;

    let envelope = format!(
        "Tokens matching `{}` are opaque anonymized identifiers. Preserve them \
         exactly — do not rename, expand, translate, pluralize, or reformat them. \
         If you introduce a new entity, name it `NEW_<n>` and list every such name \
         at the end of your response.",
        specshield_core::alias::ENVELOPE_PATTERN
    );

    let task = "Add retry with exponential backoff to the create method, and \
                write one unit test for it. Return the full file.";

    for format in FORMATS {
        let body = sample_module(format.sample);
        for (variant, preamble) in [("with-envelope", envelope.as_str()), ("no-envelope", "")] {
            let path = format!("{dir}/{}--{variant}.md", format.name);
            let content = if preamble.is_empty() {
                format!("{task}\n\n```ts\n{body}\n```\n")
            } else {
                format!("{preamble}\n\n{task}\n\n```ts\n{body}\n```\n")
            };
            std::fs::write(&path, content)?;
        }
    }

    println!("Wrote {} prompts to {dir}/", FORMATS.len() * 2);
    println!();
    println!("Part 2 procedure:");
    println!("  1. Send each prompt to each model under evaluation.");
    println!("  2. Save responses as <prompt-stem>.<model>.response.md beside the prompt.");
    println!("  3. Score: count occurrences of the exact alias vs. canonical-only");
    println!("     matches vs. tokens that no longer resolve at all.");
    println!();
    println!("This step makes external API calls and costs money, so it is left");
    println!("for a human to run deliberately rather than triggered from here.");
    Ok(())
}

fn sample_module(alias: &str) -> String {
    format!(
        "export class {alias} {{\n  \
         constructor(private readonly repo: DTO_M4X2Q7) {{}}\n\n  \
         async create(input: DTO_M4X2Q7): Promise<EVENT_K9P3Q2> {{\n    \
         return this.repo.insert(input);\n  \
         }}\n\
         }}"
    )
}
