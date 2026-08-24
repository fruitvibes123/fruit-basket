          
//! §5.3 grep-guard: the manifest/topology structs may use ONLY the whitelisted serde
//! attributes — `deny_unknown_fields`, `rename`, `rename_all`, and the default externally-tagged
//! enum derive. FORBIDDEN: `flatten`, internally-tagged (`tag = …`), `untagged`, `default`, `alias`,
//! `skip`/`skip_deserializing`/`skip_serializing` — each either silently disables the unknown-field
//! guard or widens the accepted shape past the typed contract. Mirrors the project's own grep-guard
//! pattern (`no_forbidden_crypto_deps.rs` / `tests/household_id_escape_hatch.rs` G11).

use std::fs;
use std::path::Path;

/// Substrings that must never appear inside a `#[serde(...)]` attribute in this crate's sources.
const FORBIDDEN: &[&str] = &[
    "flatten", "untagged", "default", "alias", "skip", "tag ", "tag=", "tag\t",
];

/// Collect the text of every `#[serde(...)]` attribute, joined across continuation lines and with the
/// CONTENTS of its string literals DROPPED — returned as `(1-based start line, code-only attribute)`.
///
                                
/// This is the whole-attribute span scan. A line-by-line scan cannot see
/// a wrapped attribute (`#[serde(\n    default\n)]`), and a "does the opener contain `)]`" shortcut is
/// fooled by a `)]` hiding inside a string value (`#[serde(rename = "x)]",` looks closed but is not).
/// Scanning the balanced `serde( … )` while skipping string contents closes both: the forbidden scan
/// sees the complete attribute regardless of wrapping, and a `)]` or a forbidden keyword inside a
/// `rename = "..."` value can neither fake the close nor trip the scan (so `rename = "default"` is NOT a
/// false positive). A span is started ONLY at a line that, trimmed, begins `#[serde(` — so a doc comment
/// or a raw-string TOML fixture that merely mentions it is never entered. A serde attribute's values are
/// ordinary `"…"` string literals (with `\"` escapes); the scan handles exactly that — no raw strings or
/// char literals occur *inside* an attribute, only elsewhere in the file (which the scan never enters).
///
                                 
/// ASSUMPTIONS (recorded so the guard's reach is explicit, not implied):
/// the input is valid, COMPILING Rust. So no char literal (`'"'`) appears inside a serde attribute (no
/// serde key takes one) and no string is left unterminated (a compile error) — the two shapes that could
/// otherwise desync the string tracker cannot occur in the crate this scans. And the line-start trigger
/// errs SAFE: a (hypothetical, future) raw string whose content line begins `#[serde(` would be scanned
/// as if it were an attribute → over-reject (a loud failure to fix), never a silent miss; no such fixture
/// exists today and this is pre-existing to the line-start trigger. Multiple attrs on one physical line
             
/// are handled separately by [`has_stacked_serde_attrs`].
fn serde_attribute_spans(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut spans = Vec::new();
    let mut li = 0;
    while li < lines.len() {
        if !lines[li].trim_start().starts_with("#[serde(") {
            li += 1;
            continue;
        }
        let start_line = li + 1;                                     
        let mut code = String::new();
        let mut depth: i32 = 0;
        let mut opened = false;                                                
        let mut in_str = false;
        let mut escaped = false;
        'attr: loop {
            for ch in lines[li].chars() {
                if in_str {
                                                                                               
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        in_str = false;
                    }
                    continue;
                }
                match ch {
                    '"' => in_str = true,
                    '(' => {
                        depth += 1;
                        opened = true;
                        code.push('(');
                    }
                    ')' => {
                        depth -= 1;
                        code.push(')');
                        if opened && depth == 0 {
                            break 'attr;                                                            
                        }
                    }
                    _ => code.push(ch),
                }
            }
            code.push(' ');                          
            li += 1;
            if li >= lines.len() {
                break;                                                           
            }
        }
        spans.push((start_line, code));
        li += 1;
    }
    spans
}

/// True iff `line` is an attribute line carrying MORE THAN ONE `#[serde(` (stacked attributes on one
/// physical line). [`serde_attribute_spans`] reads only the FIRST attribute per line, so a second one's
             
                        
/// forbidden token would go unseen. `cargo fmt --check` (run by the verification suite) already
/// re-wraps stacked attrs one-per-line, but enforcing one-per-line directly means the guard does not
/// silently depend on the formatter. Keyed on an attribute line (trimmed start `#[serde(`), so a doc
/// comment that merely mentions `#[serde(` twice is not caught.
fn has_stacked_serde_attrs(line: &str) -> bool {
    line.trim_start().starts_with("#[serde(") && line.matches("#[serde(").count() > 1
}

                   
/// Recursively collect every `.rs` under `dir` (a flat `read_dir` would leave a future
/// `src/<subdir>/*.rs` unscanned → coverage silently drops on a restructure).
fn collect_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_forbidden_serde_attributes_in_src() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files);                                                                             
    let mut offenders = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).expect("read src file");
        for (start_line, code) in serde_attribute_spans(&text) {
            if let Some(bad) = FORBIDDEN.iter().find(|b| code.contains(**b)) {
                offenders.push(format!(
                    "{}:{}: forbidden `{}` in serde attribute: {}",
                    path.display(),
                    start_line,
                    bad,
                    code.trim()
                ));
            }
        }
                                                                                                           
        for (i, line) in text.lines().enumerate() {
            if has_stacked_serde_attrs(line) {
                offenders.push(format!(
                                 
                    "{}:{}: multiple serde attributes on one line (one per line): {}",
                    path.display(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
                  
        "forbidden serde attribute(s) found (§5.3 whitelist):\n{}",
        offenders.join("\n")
    );
}

/// The code-only spans of `src` that carry a forbidden substring (the predicate the guard above asserts
/// empty) — the self-test's lens onto the scanner.
fn forbidden_hits(src: &str) -> Vec<String> {
    serde_attribute_spans(src)
        .into_iter()
        .filter(|(_, code)| FORBIDDEN.iter().any(|b| code.contains(b)))
        .map(|(_, code)| code)
        .collect()
}

/// Self-test (no-false-assurance: a guard that never fires is theater). Proves the scanner FIRES on every
             
/// forbidden shape — single-line, rustfmt-wrapped, AND the `)]`-inside-a-string bypass — and
/// stays quiet on the whitelisted attributes, doc-comment mentions, and a legitimate `rename = "default"`.
#[test]
fn the_guard_detects_violations_and_ignores_safe_lines() {
                                                       
    assert_eq!(forbidden_hits(r#"#[serde(default)]"#).len(), 1);
    assert_eq!(forbidden_hits(r#"#[serde(default = "f")]"#).len(), 1);
    assert_eq!(forbidden_hits(r#"#[serde(flatten)]"#).len(), 1);
    assert_eq!(forbidden_hits(r#"#[serde(tag = "type")]"#).len(), 1);
    assert_eq!(forbidden_hits(r#"#[serde(untagged)]"#).len(), 1);
    assert_eq!(forbidden_hits(r#"#[serde(alias = "x")]"#).len(), 1);
    assert_eq!(forbidden_hits(r#"#[serde(skip_deserializing)]"#).len(), 1);

                                                                                                 
    assert_eq!(forbidden_hits("#[serde(\n    default\n)]").len(), 1);

                                                                                                           
                                                                                                         
    assert_eq!(
        forbidden_hits("#[serde(rename = \"x)]\",\n    default)]").len(),
        1,
                     
        "the `)]`-inside-a-string bypass must be caught"
    );

                                                                    
    assert!(
        forbidden_hits(r#"#[serde(deny_unknown_fields, rename_all = "snake_case")]"#).is_empty()
    );
    assert!(forbidden_hits(r#"    #[serde(rename = "priv")]"#).is_empty());
    assert!(
        forbidden_hits("#[serde(\n    deny_unknown_fields,\n    rename_all = \"snake_case\"\n)]")
            .is_empty()
    );

                                                                                                          
                                                                                                      
    assert!(forbidden_hits(r#"#[serde(rename = "default")]"#).is_empty());

                                                                                                    
    assert!(
        forbidden_hits(r#"/// NO `#[serde(default)]` and no `alias` is permitted."#).is_empty()
    );

                                                                                                         
                                                                                                         
    assert!(has_stacked_serde_attrs(
        r#"#[serde(rename = "a")] #[serde(default)]"#
    ));
    assert!(!has_stacked_serde_attrs(
        r#"#[serde(deny_unknown_fields, rename_all = "snake_case")]"#
    ));
    assert!(!has_stacked_serde_attrs(
        r#"/// mentions #[serde(a)] and #[serde(b)] — a doc comment, not an attribute line"#
    ));
}
