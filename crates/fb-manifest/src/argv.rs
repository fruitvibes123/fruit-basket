//! `ArgvToken::{ Literal, Placeholder(KnownPlaceholder) }` (externally-tagged) + the typed
//! placeholder fill — a `Placeholder` is filled by MATCHING the typed variant, never by
          
//! `str::replace` over a literal stream (§5.3), so a `Literal` whose value is the text
//! `{domain}` is an inert literal, never an OS-invariant value.
//!
                            
//! The typed-fill argv model. The literal's charset is validated at the
          
//! `ValidatedManifest` gate (A.3/A.4, §5.3) — NOT here.

use serde::{Deserialize, Serialize};

/// A single token in a service / boot-hook `argv` (§5.1c/e).
///
/// **Externally-tagged** (the serde default) with struct variants + `deny_unknown_fields` (§5.3).
/// In TOML each token is a one-key table whose key is the variant: `{ literal = { value = "serve" } }`
/// or `{ placeholder = { name = "domain" } }`. Because the two variants are structurally distinct, a
/// `Literal` can NEVER be reinterpreted as a `Placeholder`: the renderer fills a `Placeholder` by
/// matching the variant (A.4), so a `Literal { value: "{source_date_epoch}" }` renders that text
/// verbatim, never the build epoch (the §9 positive proof).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ArgvToken {
              
    /// A literal command-line token (a whole shell word). Its value is charset-validated (§5.3)
    /// at the `ValidatedManifest` gate before it can reach a rendered `#!/bin/sh` word position.
    Literal { value: String },
    /// An OS-invariant placeholder (a whole shell word) the renderer fills from the build context (the
    /// box domain, the build epoch). The fill is a typed-variant match (A.4), never string substitution.
    Placeholder { name: KnownPlaceholder },
    /// A single shell word made of mixed fragments — for a placeholder EMBEDDED inside a word (e.g. a
    /// cert path `/persist/acme/{domain}/full.pem`). The fragments concatenate WITHIN the word (no
              
    /// space-splitting); `Literal`/`Placeholder` are the concise whole-word cases. §5.3 holds: a
    /// `Literal` fragment of the text `{domain}` stays that text (each `Literal` fragment is
              
    /// charset-validated at the gate, §5.3).
    Template { fragments: Vec<ArgvFragment> },
}

/// A fragment of a [`ArgvToken::Template`] word — literal text or an OS-invariant placeholder,
/// concatenated within ONE shell word. Same shape as the env-value `EnvFragment`, but for a shell word:
          
/// each `Literal` fragment is charset-validated (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ArgvFragment {
    /// Literal text within the word (charset-validated at the gate).
    Literal { value: String },
    /// An OS-invariant placeholder filled within the word.
    Placeholder { name: KnownPlaceholder },
}

          
/// The CLOSED set of OS-invariant placeholders the renderer can fill (§5.3).
///
/// A closed enum, NOT a string match — so no tenant-supplied `Literal` string can ever name a
/// placeholder. A fieldless choice deserialized from a scalar string (`name = "domain"`); an unknown
/// name fails closed (`unknown variant`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownPlaceholder {
    /// The box's configured domain (`{domain}` in today's hardcoded templates).
    Domain,
    /// The build-time `SOURCE_DATE_EPOCH` clock floor (`{source_date_epoch}`).
    SourceDateEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test wrapper: TOML needs a table at top level, so wrap the token list.
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct W {
        argv: Vec<ArgvToken>,
    }

    fn parse(s: &str) -> Result<W, toml::de::Error> {
        toml::from_str(s)
    }

    #[test]
    fn parses_a_mixed_literal_and_placeholder_argv() {
        let w = parse(
            r#"
            argv = [
                { literal = { value = "renew" } },
                { literal = { value = "--domain" } },
                { placeholder = { name = "domain" } },
                { literal = { value = "--min-epoch" } },
                { placeholder = { name = "source_date_epoch" } },
            ]
            "#,
        )
        .expect("valid argv parses");
        assert_eq!(
            w.argv,
            vec![
                ArgvToken::Literal {
                    value: "renew".into()
                },
                ArgvToken::Literal {
                    value: "--domain".into()
                },
                ArgvToken::Placeholder {
                    name: KnownPlaceholder::Domain
                },
                ArgvToken::Literal {
                    value: "--min-epoch".into()
                },
                ArgvToken::Placeholder {
                    name: KnownPlaceholder::SourceDateEpoch
                },
            ]
        );
    }

    #[test]
    fn a_literal_of_a_placeholder_string_stays_a_literal() {
                                                                                                   
                                                                                                        
        let w = parse(r#"argv = [ { literal = { value = "{source_date_epoch}" } } ]"#)
            .expect("a literal of placeholder-looking text is a valid literal");
        assert_eq!(
            w.argv,
            vec![ArgvToken::Literal {
                value: "{source_date_epoch}".into()
            }]
        );
                                   
        assert!(!matches!(w.argv[0], ArgvToken::Placeholder { .. }));
    }

    #[test]
    fn unknown_variant_is_refused() {
        let err = parse(r#"argv = [ { exec = { value = "x" } } ]"#).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant") || err.to_string().contains("exec"),
            "unknown variant must fail closed: {err}"
        );
    }

    #[test]
    fn unknown_field_in_a_variant_is_refused() {
                                                                                      
        let err = parse(r#"argv = [ { literal = { value = "x", evil = "y" } } ]"#).unwrap_err();
        assert!(
            err.to_string().contains("evil") || err.to_string().contains("unknown"),
            "{err}"
        );
    }

    #[test]
    fn unknown_placeholder_name_is_refused() {
        let err = parse(r#"argv = [ { placeholder = { name = "root_password" } } ]"#).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant")
                || err.to_string().contains("root_password"),
            "an unknown placeholder name must fail closed: {err}"
        );
    }

    #[test]
    fn two_variant_keys_in_one_token_is_refused() {
                                                                                                      
                                                                               
        let err =
            parse(r#"argv = [ { literal = { value = "x" }, placeholder = { name = "domain" } } ]"#)
                .unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "multi-variant token must fail: {err}"
        );
    }
}
