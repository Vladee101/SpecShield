//! Path and filename aliasing — SDD §4.1, PRD FR-3b. **M4.**
//!
//! A file tree is proprietary on its own. `src/meridian-freight/billing.ts`
//! names a client with no identifier in it at all, and an export that wrote the
//! twin at the real paths would hand that over untouched.
//!
//! The hard constraint is that the tree and the code must agree. A TypeScript
//! file importing `"../domain/customer-subscription"` has that specifier
//! rewritten by the parser; if the file itself is written under a different
//! name, the twin does not resolve and stops being a project a model can reason
//! about. Both sides therefore go through [`segment_identity`] and land on the
//! same identity — and so, deterministically, the same alias.

use crate::model::{EntityType, IdentityKey};
use crate::parser::{ProjectContext, fold_name};

/// Path segments are scoped to the project, not to the file that mentions them.
///
/// The file `src/domain/customer-subscription.ts` and every import of it are
/// one name for one thing. Scoping the segment per importing file — which is
/// what the parser did first — gave two importers two different aliases for the
/// same module, and then the file itself could only be written under one of
/// them.
pub const PATH_SCOPE: &str = "path";

/// Is this path segment an entity, or is it structure?
///
/// Two ways in, and both are needed:
///
/// - **Compound.** `customer-subscription` mirrors `CustomerSubscription` and
///   leaks it whether or not this build has seen that type.
/// - **A name the project knows.** `thing18.ts` holding `Thing18` is the
///   dominant convention in TypeScript, and the export gate — which folds case
///   and separators — reads `thing18` as that type's name.
///
/// Neither: `subscription`, the stem of `subscription.repository.ts`, is a
/// common noun and a local variable in half the files of a service. Aliasing it
/// blocked the export on every `const subscription = …`. `domain`, `dto`, `src`
/// are architectural convention, universal across projects, and aliasing them
/// makes every import unreadable for nothing.
///
/// A single-word directory or file name that *is* proprietary is what the
/// dictionary is for.
#[must_use]
pub fn is_entity_segment(stem: &str, context: &ProjectContext) -> bool {
    if stem.is_empty() {
        return false;
    }
    stem.contains(['-', '_']) || context.knows_folded(&fold_name(stem))
}

/// The identity a path segment carries, wherever it is written.
#[must_use]
pub fn segment_identity(stem: &str) -> IdentityKey {
    IdentityKey::new(PATH_SCOPE, EntityType::PathSegment, stem)
}

/// Extensions a module resolver drops. `import "./x"` finds `x.ts`.
///
/// This list is what defines where a filename ends and its type begins, and it
/// has to, because the *import specifier* is the other half of the pair: the
/// file `create-subscription.dto.ts` is imported as
/// `"../dto/create-subscription.dto"`, so the name is `create-subscription.dto`
/// and `.ts` is the only part the resolver adds back. Splitting anywhere else
/// gives the file one alias and its importers another, and the twin no longer
/// resolves.
const MODULE_EXTENSIONS: &[&str] = &[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json"];

/// Split a filename into the name an import specifier would use and the
/// extension a resolver adds back.
#[must_use]
pub fn split_module_stem(component: &str) -> (&str, &str) {
    for extension in MODULE_EXTENSIONS {
        if let Some(stem) = component.strip_suffix(extension) {
            // A dotfile named exactly like an extension is a name, not a suffix.
            if !stem.is_empty() {
                return (stem, extension);
            }
        }
    }
    (component, "")
}

/// One component of a path, and what the caller has to do with it.
///
/// Core decides *which* mechanism a component belongs to; the caller resolves
/// it, because both mechanisms need the identity graph and only the caller
/// holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Component {
    /// A segment entity: alias `key`, then re-attach `suffix`.
    Segment { key: IdentityKey, suffix: String },
    /// Anything else — hand `text` to the detector, then re-attach `suffix`.
    ///
    /// The suffix is a *file's* final extension, held back deliberately. Handed
    /// the whole of `subscription.repository.ts`, the detector's hostname rule
    /// matches it end to end — three dotted segments ending in two letters is
    /// exactly a hostname — and the file comes out as `HOST_8AWS33` with no
    /// extension at all. A twin that is not a TypeScript project any more is
    /// not a twin.
    Text { text: String, suffix: String },
}

/// Split a path into components and classify each one.
///
/// Two mechanisms, in the order the content pipeline uses them, because a path
/// inside an import string goes through exactly these and the file tree has to
/// come out the same:
///
/// 1. **The segment rule.** `customer-subscription.ts` is the segment
///    `customer-subscription` wearing `.ts`, and the parser claims that same
///    span inside `"../domain/customer-subscription"`. Same identity, same
///    alias, so the import still resolves to the file.
/// 2. **Everything else is [`Component::Text`]**, for the detector.
///    `subscription.repository.ts` is not a segment entity — `subscription`
///    alone is a common noun — but `subscription.repository` is how
///    `SubscriptionRepository` looks written in a path, and the detector's
///    case-variant pass matches it in the import string. Running the same pass
///    over the filename is what keeps the two in step.
///
/// Skipping step 2 is not a smaller version of this: it leaves the twin tree
/// carrying a name the twin's own contents alias, which the export gate then
/// blocks on — as it did.
#[must_use]
pub fn components(path: &str, context: &ProjectContext) -> Vec<Component> {
    let count = path.split('/').count();
    path.split('/')
        .enumerate()
        .map(|(i, component)| {
            let is_file = i + 1 == count;
            let (stem, suffix) = if is_file {
                split_module_stem(component)
            } else {
                (component, "")
            };
            if is_entity_segment(stem, context) {
                return Component::Segment {
                    key: segment_identity(stem),
                    suffix: suffix.to_owned(),
                };
            }
            // A different split, for a different question. The segment rule
            // above asks "what would an import call this file"; here we only
            // need to keep the detector's hostname rule off the extension, and
            // that is the final dot whatever it is. Only a file has one — a
            // directory called `api.internal` keeps its dot and goes to the
            // detector whole.
            let (text, suffix) = if is_file {
                split_extension(component)
            } else {
                (component, "")
            };
            Component::Text {
                text: text.to_owned(),
                suffix: suffix.to_owned(),
            }
        })
        .collect()
}

/// Split off a file's final extension. A dotfile has none: `.gitignore` is a
/// name, not a suffix.
#[must_use]
pub fn split_extension(component: &str) -> (&str, &str) {
    match component.rfind('.') {
        Some(0) | None => (component, ""),
        Some(dot) => component.split_at(dot),
    }
}

/// Rewrite one `/`-separated relative path, resolving each component.
pub fn twin_path(path: &str, context: &ProjectContext, mut resolve: impl FnMut(&Component) -> String) -> String {
    components(path, context)
        .iter()
        .map(&mut resolve)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(names: &[&str]) -> ProjectContext {
        ProjectContext::new(std::iter::empty(), names.iter().map(|n| (*n).to_owned()))
    }

    /// A resolver that names segments after their real name, so a test can see
    /// which mechanism fired without caring what alias came out.
    fn resolve(component: &Component) -> String {
        match component {
            Component::Segment { key, suffix } => format!("<{}>{suffix}", key.real_name),
            Component::Text { text, suffix } => format!("{text}{suffix}"),
        }
    }

    #[test]
    fn a_filename_is_named_the_way_an_import_names_it() {
        // `create-subscription.dto.ts` is imported as
        // `"../dto/create-subscription.dto"`, so that is the name and `.ts` is
        // the only part the resolver adds back. Splitting at the first dot
        // instead gave the file one alias and its importers another.
        let context = context(&[]);
        let twin = twin_path("src/dto/create-subscription.dto.ts", &context, resolve);
        assert_eq!(twin, "src/dto/<create-subscription.dto>.ts");
    }

    #[test]
    fn architectural_directories_are_left_alone() {
        // `src`, `dto`, and `domain` are the same in every project on earth.
        let context = context(&[]);
        let twin = twin_path("src/domain/plan-tier.ts", &context, resolve);
        assert_eq!(twin, "src/domain/<plan-tier>.ts");
    }

    #[test]
    fn a_single_word_module_named_after_a_type_the_project_knows_is_an_entity() {
        let context = context(&["Thing18"]);
        assert_eq!(twin_path("src/thing18.ts", &context, resolve), "src/<thing18>.ts");
    }

    #[test]
    fn a_dotted_filename_the_project_knows_is_a_segment() {
        // `subscription` alone is a common noun and a local variable in half
        // the service, so the first dot is the wrong place to stop. The whole
        // `subscription.repository` is how `SubscriptionRepository` looks
        // written in a path, and it is what the import says.
        let context = context(&["SubscriptionRepository"]);
        assert_eq!(
            twin_path("src/repositories/subscription.repository.ts", &context, resolve),
            "src/repositories/<subscription.repository>.ts"
        );
    }

    #[test]
    fn a_filename_that_names_nothing_still_goes_to_the_detector() {
        // The fallback earns its place on names no segment rule recognises: a
        // directory named after a client is a leak with no identifier in it.
        let context = context(&[]);
        assert_eq!(
            twin_path("meridian-freight/README.md", &context, |c| match c {
                Component::Segment { key, suffix } => format!("<{}>{suffix}", key.real_name),
                Component::Text { text, suffix } => format!("[{text}]{suffix}"),
            }),
            "<meridian-freight>/[README].md"
        );
    }

    #[test]
    fn a_files_extension_is_held_back_from_the_detector() {
        // Handed the whole component, the hostname rule matches
        // `subscription.repository.ts` end to end and the twin loses its
        // extension.
        let context = context(&[]);
        let parts = components("src/repositories/subscription.repository.ts", &context);
        assert_eq!(
            parts.last(),
            Some(&Component::Text {
                text: "subscription.repository".to_owned(),
                suffix: ".ts".to_owned(),
            })
        );
    }

    #[test]
    fn a_directory_keeps_its_dots() {
        // Only a file has an extension.
        let context = context(&[]);
        let parts = components("api.internal/handler.ts", &context);
        assert_eq!(
            parts.first(),
            Some(&Component::Text {
                text: "api.internal".to_owned(),
                suffix: String::new(),
            })
        );
    }

    #[test]
    fn a_dotfile_names_nothing() {
        let context = context(&[]);
        assert_eq!(twin_path(".gitignore", &context, resolve), ".gitignore");
    }

    #[test]
    fn the_same_segment_lands_on_the_same_identity_wherever_it_appears() {
        // The file and every import of it must agree, or the twin does not
        // resolve.
        assert_eq!(
            segment_identity("customer-subscription"),
            segment_identity("customer-subscription")
        );
    }
}
