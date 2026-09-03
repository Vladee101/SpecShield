//! What counts as an identifying name — PRD §4.
//!
//! SpecShield strips the names that say who you are and what you built. It is
//! not a redaction engine for every token in a repository, and the difference is
//! the whole usability of the tool: a twin in which `Node`, `Screen`, `data` and
//! `status` are opaque aliases is unreadable, produces worse model output, and
//! turns the export gate into a wall of noise. A real React project put 124
//! distinct names in front of the gate, almost all of them ordinary words, and
//! `node` alone accounted for 1,879 of the hits — nearly every one inside
//! `package-lock.json`, where it is npm's word and not the user's.
//!
//! So: **a name made of one common English word is not identifying.** Two rules
//! follow from that, and one exception overrides both.
//!
//! - A **compound** name is identifying. `CustomerSubscription`, `plan_tier`,
//!   `subscription-service` — the combination is the user's, whatever the parts
//!   are. This is where nearly all real proprietary naming lives.
//! - A **single word that is not in ordinary use** is identifying. `Vantor`,
//!   `Paylane`, `Meridian` — an invented proper noun is exactly the thing worth
//!   hiding, and it is not in this list.
//! - **A name the user has confirmed always wins.** `specshield term account
//!   --entity-type table` says *this common word is mine*, and it is aliased
//!   from then on. That is the escape hatch, and it is the mirror of the
//!   allowlist: one says "this generic word is mine", the other says "this name
//!   of mine is generic".
//!
//! The cost is real and is not hidden. A table called `invoice` in a
//! proprietary billing schema is proprietary, and this rule leaves it in the
//! twin. `specshield report` measures it: recall over compound names is what the
//! product now gates on, and recall over single common words is reported beside
//! it so the trade is visible rather than assumed.

use std::sync::LazyLock;

use std::collections::HashSet;

/// Below this, a name is not identifying on its own whatever it says.
const MIN_LEN: usize = 3;

/// Ordinary English and ordinary software vocabulary.
///
/// Deliberately a fixed list rather than a dictionary file or a frequency
/// model: it has to be greppable, reviewable in a diff, and identical on every
/// machine. A user who disagrees about one word does not edit this — they run
/// `specshield term` and the disagreement is recorded in their vault.
///
/// Compared lowercased, so `Node`, `node` and `NODE` are one entry.
const COMMON: &[&str] = &[
    "account",
    "action",
    "actions",
    "active",
    "address",
    "admin",
    "alert",
    "alerts",
    "all",
    "amount",
    "answer",
    "api",
    "app",
    "apps",
    "arg",
    "args",
    "array",
    "asset",
    "assets",
    "attempt",
    "attribute",
    "auth",
    "author",
    "avatar",
    "backup",
    "badge",
    "balance",
    "banner",
    "base",
    "batch",
    "billing",
    "block",
    "blocks",
    "body",
    "bool",
    "boolean",
    "border",
    "branch",
    "budget",
    "buffer",
    "build",
    "bundle",
    "button",
    "cache",
    "calendar",
    "call",
    "callback",
    "cancel",
    "candidate",
    "canvas",
    "capacity",
    "card",
    "cart",
    "case",
    "catalog",
    "category",
    "cell",
    "chain",
    "change",
    "changes",
    "channel",
    "chart",
    "charts",
    "check",
    "child",
    "children",
    "choice",
    "choices",
    "chunk",
    "claim",
    "class",
    "click",
    "client",
    "clients",
    "clock",
    "cluster",
    "code",
    "codes",
    "collection",
    "color",
    "column",
    "columns",
    "command",
    "comment",
    "comments",
    "commit",
    "company",
    "complete",
    "component",
    "components",
    "config",
    "connection",
    "console",
    "constant",
    "consumer",
    "container",
    "content",
    "context",
    "control",
    "cookie",
    "copy",
    "core",
    "correct",
    "count",
    "counter",
    "country",
    "coupon",
    "create",
    "created",
    "credit",
    "criteria",
    "currency",
    "current",
    "cursor",
    "custom",
    "customer",
    "data",
    "database",
    "date",
    "datetime",
    "day",
    "days",
    "debug",
    "decision",
    "default",
    "delete",
    "delivery",
    "delta",
    "description",
    "detail",
    "details",
    "device",
    "dialog",
    "diff",
    "dimension",
    "directory",
    "discount",
    "display",
    "document",
    "documents",
    "domain",
    "done",
    "draft",
    "driver",
    "duration",
    "edge",
    "edit",
    "editor",
    "element",
    "elements",
    "email",
    "emails",
    "empty",
    "enabled",
    "end",
    "endpoint",
    "engine",
    "entity",
    "entries",
    "entry",
    "env",
    "environment",
    "error",
    "errors",
    "event",
    "events",
    "example",
    "exception",
    "execute",
    "expiry",
    "export",
    "extension",
    "external",
    "factory",
    "fail",
    "failed",
    "failure",
    "feature",
    "features",
    "feed",
    "feedback",
    "field",
    "fields",
    "file",
    "files",
    "filter",
    "filters",
    "flag",
    "flags",
    "flow",
    "folder",
    "font",
    "footer",
    "form",
    "format",
    "forward",
    "frame",
    "from",
    "function",
    "gateway",
    "grade",
    "grades",
    "graph",
    "grid",
    "group",
    "groups",
    "guard",
    "handler",
    "hash",
    "header",
    "headers",
    "health",
    "height",
    "helper",
    "hidden",
    "history",
    "home",
    "host",
    "hour",
    "hours",
    "html",
    "icon",
    "icons",
    "identity",
    "image",
    "images",
    "import",
    "inbox",
    "index",
    "info",
    "input",
    "inputs",
    "instance",
    "integration",
    "interface",
    "internal",
    "interval",
    "invalid",
    "inventory",
    "invoice",
    "invoices",
    "issue",
    "item",
    "items",
    "job",
    "jobs",
    "json",
    "key",
    "keys",
    "kind",
    "label",
    "labels",
    "language",
    "layer",
    "layout",
    "left",
    "legend",
    "length",
    "level",
    "levels",
    "library",
    "license",
    "limit",
    "line",
    "lines",
    "link",
    "links",
    "list",
    "listener",
    "loader",
    "loading",
    "local",
    "location",
    "lock",
    "log",
    "logger",
    "login",
    "logout",
    "logs",
    "loop",
    "main",
    "manager",
    "map",
    "mapper",
    "margin",
    "mark",
    "marker",
    "market",
    "match",
    "matrix",
    "max",
    "media",
    "member",
    "members",
    "menu",
    "message",
    "messages",
    "meta",
    "method",
    "methods",
    "metric",
    "metrics",
    "middleware",
    "migration",
    "milestone",
    "min",
    "minute",
    "minutes",
    "modal",
    "mode",
    "model",
    "models",
    "module",
    "month",
    "mount",
    "name",
    "names",
    "navigation",
    "network",
    "new",
    "next",
    "node",
    "nodes",
    "note",
    "notes",
    "notification",
    "null",
    "number",
    "object",
    "offer",
    "offset",
    "old",
    "operation",
    "option",
    "options",
    "order",
    "orders",
    "output",
    "overlay",
    "override",
    "owner",
    "package",
    "padding",
    "page",
    "pages",
    "pair",
    "panel",
    "param",
    "parameter",
    "params",
    "parent",
    "parser",
    "partition",
    "partitions",
    "password",
    "patch",
    "path",
    "paths",
    "pattern",
    "payload",
    "payment",
    "payments",
    "payout",
    "pending",
    "period",
    "permission",
    "permissions",
    "person",
    "phase",
    "phone",
    "pipeline",
    "plan",
    "plans",
    "platform",
    "player",
    "plugin",
    "point",
    "points",
    "policy",
    "pool",
    "port",
    "portal",
    "position",
    "post",
    "preview",
    "price",
    "pricing",
    "primary",
    "priority",
    "private",
    "process",
    "producer",
    "product",
    "products",
    "profile",
    "progress",
    "project",
    "projects",
    "prompt",
    "property",
    "props",
    "protocol",
    "provider",
    "proxy",
    "public",
    "publish",
    "query",
    "question",
    "questions",
    "queue",
    "range",
    "rate",
    "rating",
    "read",
    "reader",
    "reason",
    "receipt",
    "record",
    "records",
    "reducer",
    "ref",
    "reference",
    "refresh",
    "refund",
    "region",
    "register",
    "registry",
    "release",
    "remote",
    "render",
    "repository",
    "request",
    "requests",
    "required",
    "reset",
    "resolve",
    "resource",
    "resources",
    "response",
    "responses",
    "result",
    "results",
    "retention",
    "retry",
    "return",
    "review",
    "right",
    "role",
    "roles",
    "root",
    "route",
    "router",
    "routes",
    "row",
    "rows",
    "rule",
    "rules",
    "run",
    "runner",
    "sale",
    "sales",
    "sample",
    "save",
    "scale",
    "scan",
    "scenario",
    "scenarios",
    "schedule",
    "schema",
    "scope",
    "score",
    "screen",
    "script",
    "search",
    "second",
    "seconds",
    "secret",
    "section",
    "security",
    "select",
    "selection",
    "server",
    "service",
    "services",
    "session",
    "set",
    "setting",
    "settings",
    "setup",
    "shape",
    "share",
    "sheet",
    "shell",
    "shipping",
    "sidebar",
    "signal",
    "signature",
    "site",
    "size",
    "skill",
    "skills",
    "slot",
    "snapshot",
    "socket",
    "sort",
    "source",
    "space",
    "span",
    "spec",
    "stack",
    "stage",
    "stages",
    "start",
    "state",
    "states",
    "static",
    "statistics",
    "stats",
    "status",
    "step",
    "steps",
    "stock",
    "storage",
    "store",
    "stream",
    "string",
    "style",
    "styles",
    "submit",
    "subscription",
    "subscriptions",
    "succeeded",
    "success",
    "suffix",
    "summary",
    "support",
    "switch",
    "symbol",
    "sync",
    "system",
    "tab",
    "table",
    "tables",
    "tag",
    "tags",
    "target",
    "task",
    "tasks",
    "tax",
    "team",
    "teams",
    "template",
    "test",
    "tests",
    "text",
    "theme",
    "thread",
    "ticket",
    "tier",
    "time",
    "timeline",
    "timeout",
    "timer",
    "title",
    "toast",
    "toggle",
    "token",
    "tokens",
    "tool",
    "tools",
    "tooltip",
    "topic",
    "total",
    "trace",
    "track",
    "transaction",
    "transfer",
    "tree",
    "trigger",
    "type",
    "types",
    "unit",
    "units",
    "update",
    "upload",
    "url",
    "usage",
    "user",
    "users",
    "utility",
    "utils",
    "valid",
    "validation",
    "value",
    "values",
    "variable",
    "vendor",
    "version",
    "video",
    "view",
    "views",
    "warning",
    "week",
    "widget",
    "width",
    "window",
    "worker",
    "workflow",
    "wrapper",
    "write",
    "year",
    "zone",
];

static LOOKUP: LazyLock<HashSet<&'static str>> = LazyLock::new(|| COMMON.iter().copied().collect());

/// Is this name identifying on its own? — PRD §4.
///
/// `false` means "ordinary word, not worth hiding, leave it in the twin". It is
/// never the last word: a name the user has confirmed with `specshield term` is
/// aliased regardless, and callers check that first.
#[must_use]
pub fn is_identifying(name: &str) -> bool {
    if name.len() < MIN_LEN {
        return false;
    }
    // A compound is the user's, whatever its parts are. `plan_tier` and
    // `PlanTier` are both two words, and neither is in ordinary use.
    if segments(name) > 1 {
        return true;
    }
    !LOOKUP.contains(name.to_lowercase().as_str())
}

/// How many words a name is made of.
///
/// Splits on the separators identifiers actually use and on camelCase humps. A
/// run of capitals is one segment, so `API` is one word and `APIKey` is two —
/// otherwise every acronym would look compound and slip past the whole test.
fn segments(name: &str) -> usize {
    let chars: Vec<char> = name.chars().collect();
    let mut count = 0;
    let mut in_word = false;

    for (i, &ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            in_word = false;
            continue;
        }
        let previous = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1).copied();

        let starts = !in_word
            // `planTier` — a capital after a lower-case letter or a digit.
            || previous.is_some_and(|p| ch.is_uppercase() && !p.is_uppercase())
            // `APIKey` — the last capital of a run, when a lower-case letter
            // follows it. Without this the `K` would be swallowed by `API`.
            || (ch.is_uppercase()
                && previous.is_some_and(char::is_uppercase)
                && next.is_some_and(char::is_lowercase));

        if starts {
            count += 1;
        }
        in_word = true;
    }
    count.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compound_is_identifying_however_ordinary_its_parts() {
        // Every part of `customer_subscription` is in the list above. The
        // combination is not, and the combination is what a company names.
        for name in [
            "CustomerSubscription",
            "customer_subscription",
            "plan_tier",
            "PlanTier",
            "subscription-service",
            "SubscriptionCreated",
            "getInvoice",
            "APIKey",
        ] {
            assert!(is_identifying(name), "{name} must still be aliased");
        }
    }

    #[test]
    fn a_single_ordinary_word_is_not() {
        // The ones that made a real repository unexportable.
        for name in [
            "node", "Node", "NODE", "screen", "Screen", "choice", "data", "status", "type", "title", "error", "key",
            "context", "summary", "invoice", "account", "submit", "render", "tier",
        ] {
            assert!(!is_identifying(name), "{name} is an ordinary word");
        }
    }

    #[test]
    fn an_invented_name_is_identifying_even_alone() {
        // The whole point. A single word can be the most identifying thing in a
        // repository — it is just not a word anyone else uses.
        for name in ["Vantor", "Paylane", "Meridian", "Stripe", "Twilio", "Kubernetes"] {
            assert!(is_identifying(name), "{name} is nobody else's word");
        }
    }

    #[test]
    fn very_short_names_are_never_identifying() {
        for name in ["id", "db", "x", ""] {
            assert!(!is_identifying(name));
        }
    }

    #[test]
    fn an_acronym_run_is_one_segment() {
        // Without this every acronym would count as several words and sail
        // through the compound rule, which would defeat the whole test.
        assert_eq!(segments("API"), 1);
        assert_eq!(segments("APIKey"), 2);
        assert_eq!(segments("CustomerSubscription"), 2);
        assert_eq!(segments("plan_tier"), 2);
        assert_eq!(segments("node"), 1);
        assert_eq!(segments("Node"), 1);
    }

    #[test]
    fn the_list_is_lowercase_and_unique() {
        // It is compared lowercased; an uppercase entry would be dead weight
        // that reads as though it were doing something.
        let mut seen = HashSet::new();
        for word in COMMON {
            assert_eq!(*word, word.to_lowercase(), "{word} must be lowercase");
            assert!(seen.insert(*word), "{word} appears twice");
        }
    }
}
