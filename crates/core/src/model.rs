//! Identity graph data model — SDD §5.
//!
//! The load-bearing decision here is [`IdentityKey`]: an entity is identified by
//! the triple `(scope_path, entity_type, real_name)`, never by name alone.
//! `customer_id` exists in a dozen tables and `Status` is an enum in three
//! modules; collapsing them causes over-aliasing and ambiguous restoration at
//! the same time (Design Review B1).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Entity categories the extractor can produce — SDD §4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Organization,
    Service,
    Api,
    Endpoint,
    Table,
    Column,
    Dto,
    Interface,
    Enum,
    Event,
    Index,
    EnvVar,
    Host,
    PathSegment,
}

impl EntityType {
    /// Alias prefix for this type — the `prefix` production of the alias
    /// grammar in SDD §6.3. Frozen: changing any of these invalidates every
    /// stored alias and requires a vault migration.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Organization => "ORG",
            Self::Service => "SERVICE",
            Self::Api => "API",
            Self::Endpoint => "ENDPOINT",
            Self::Table => "DB_TABLE",
            Self::Column => "COLUMN",
            Self::Dto => "DTO",
            Self::Interface => "IFACE",
            Self::Enum => "ENUM",
            Self::Event => "EVENT",
            Self::Index => "INDEX",
            Self::EnvVar => "ENV",
            Self::Host => "HOST",
            Self::PathSegment => "PATH",
        }
    }

    /// Generic category word used by [`AliasStyle::Typed`], which keeps the
    /// category and hides the subject — SDD §6.2.
    ///
    /// [`AliasStyle::Typed`]: crate::alias::AliasStyle::Typed
    pub const fn category(self) -> &'static str {
        match self {
            Self::Organization => "Org",
            Self::Service | Self::Api => "Service",
            Self::Endpoint => "Endpoint",
            Self::Table | Self::Column => "Data",
            Self::Dto | Self::Interface => "Model",
            Self::Enum => "Enum",
            Self::Event => "Event",
            Self::Index => "Index",
            Self::EnvVar | Self::Host => "Config",
            Self::PathSegment => "Path",
        }
    }

    /// Does this kind of name say **who you are**, rather than what you built?
    ///
    /// The distinction the product turns on — PRD §4.1. An AI agent has to see
    /// the architecture to work on it: a twin in which `CustomerSubscription` is
    /// `CoreModel_8WFF40` and `chargeInvoice` is `SERVICE_QQ21XV` tells the
    /// model nothing it can build on, and asking it to extend a system it cannot
    /// read is the opposite of the point.
    ///
    /// What must not travel is the identity wrapped around that architecture:
    /// the company, the client, the vendor, the host it runs on. Those are
    /// aliased by default. Everything else is left in the clear unless the user
    /// names it with `specshield term`, which promotes any name to an identity.
    ///
    /// Secrets are neither: they are redacted one-way and never enter the graph
    /// (SDD §4.3).
    pub const fn is_identity(self) -> bool {
        match self {
            // Who you are, who you work with, and where it runs.
            Self::Organization | Self::Host => true,
            // What you built. The model needs these.
            Self::Service
            | Self::Api
            | Self::Endpoint
            | Self::Table
            | Self::Column
            | Self::Dto
            | Self::Interface
            | Self::Enum
            | Self::Event
            | Self::Index
            | Self::EnvVar
            | Self::PathSegment => false,
        }
    }

    /// Every variant, for exhaustive iteration in tests and UI.
    pub const ALL: [Self; 14] = [
        Self::Organization,
        Self::Service,
        Self::Api,
        Self::Endpoint,
        Self::Table,
        Self::Column,
        Self::Dto,
        Self::Interface,
        Self::Enum,
        Self::Event,
        Self::Index,
        Self::EnvVar,
        Self::Host,
        Self::PathSegment,
    ];
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

/// Failed to parse an [`EntityType`] from its stored string form.
#[derive(Debug, thiserror::Error)]
#[error("unknown entity type: {0}")]
pub struct UnknownEntityType(String);

impl FromStr for EntityType {
    type Err = UnknownEntityType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|t| t.prefix().eq_ignore_ascii_case(s))
            .ok_or_else(|| UnknownEntityType(s.to_owned()))
    }
}

/// The identity key — SDD §5. Backed by `ux_identity` in the vault schema
/// (SDD §9.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdentityKey {
    /// Resolver-dependent qualifier. SQL: `db.schema.table[.column]`.
    /// TypeScript: `module/path.ts::EnclosingDecl`. Markdown: `project`.
    pub scope_path: String,
    pub entity_type: EntityType,
    pub real_name: String,
}

impl IdentityKey {
    pub fn new(scope_path: impl Into<String>, entity_type: EntityType, real_name: impl Into<String>) -> Self {
        Self {
            scope_path: scope_path.into(),
            entity_type,
            real_name: real_name.into(),
        }
    }

    /// Canonical byte encoding fed to the alias HMAC — SDD §6.1.
    ///
    /// The separator must never appear unescaped in a component, or two
    /// distinct keys could hash to the same alias.
    pub(crate) fn hmac_input(&self) -> String {
        format!(
            "{}:{}:{}",
            self.scope_path.replace(':', "::"),
            self.entity_type.prefix(),
            self.real_name
        )
    }
}

/// How an identity entered the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Detected,
    Manual,
    /// Introduced by the model and named by the user — SDD §12.
    AiNew,
}

/// Lifecycle state of an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    /// Never aliased — allowlisted framework or vendor name (PRD FR-10).
    Excluded,
    /// Alias-shaped token seen in AI output with no matching identity.
    Unresolved,
}

/// A node in the identity graph — SDD §5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityNode {
    pub uuid: Uuid,
    pub key: IdentityKey,
    pub alias: String,
    pub origin: Origin,
    pub status: Status,
}

/// What kind of position an occurrence was found in — SDD §9.1 `occurrences`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceKind {
    Declaration,
    Reference,
    Comment,
    StringLiteral,
    Path,
}

impl OccurrenceKind {
    /// Stored form — the `occurrences.kind` column of SDD §9.1. Frozen in the
    /// same way alias prefixes are: rows written by an older build are read
    /// back by a newer one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declaration => "declaration",
            Self::Reference => "reference",
            Self::Comment => "comment",
            Self::StringLiteral => "string_literal",
            Self::Path => "path",
        }
    }

    pub const ALL: [Self; 5] = [
        Self::Declaration,
        Self::Reference,
        Self::Comment,
        Self::StringLiteral,
        Self::Path,
    ];
}

impl fmt::Display for OccurrenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failed to parse an [`OccurrenceKind`] from its stored string form.
#[derive(Debug, thiserror::Error)]
#[error("unknown occurrence kind: {0}")]
pub struct UnknownOccurrenceKind(String);

impl FromStr for OccurrenceKind {
    type Err = UnknownOccurrenceKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| UnknownOccurrenceKind(s.to_owned()))
    }
}

/// One byte range in one file where an identity appears.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Occurrence {
    pub identity: Uuid,
    pub file: Uuid,
    pub byte_start: usize,
    pub byte_end: usize,
    pub kind: OccurrenceKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_type_roundtrips_through_its_prefix() {
        for t in EntityType::ALL {
            assert_eq!(t.prefix().parse::<EntityType>().unwrap(), t);
        }
    }

    #[test]
    fn occurrence_kind_roundtrips_through_its_stored_form() {
        // The `occurrences` table stores this as text. A variant that does not
        // read back is a row nobody can interpret.
        for k in OccurrenceKind::ALL {
            assert_eq!(k.as_str().parse::<OccurrenceKind>().unwrap(), k);
        }
    }

    #[test]
    fn only_identity_types_are_aliased_by_default() {
        // Pinned as a list rather than a rule, because it is a product
        // decision and not a derivation: someone adding an entity type has to
        // decide which side it falls on, and this test makes them.
        let identity: Vec<&str> = EntityType::ALL
            .into_iter()
            .filter(|t| t.is_identity())
            .map(EntityType::prefix)
            .collect();
        assert_eq!(identity, vec!["ORG", "HOST"]);
    }

    #[test]
    fn prefixes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in EntityType::ALL {
            assert!(seen.insert(t.prefix()), "duplicate prefix {}", t.prefix());
        }
    }

    #[test]
    fn scope_separator_is_escaped_so_distinct_keys_cannot_collide() {
        let a = IdentityKey::new("a:b", EntityType::Service, "X");
        let b = IdentityKey::new("a", EntityType::Service, "b:X");
        assert_ne!(a.hmac_input(), b.hmac_input());
    }
}
