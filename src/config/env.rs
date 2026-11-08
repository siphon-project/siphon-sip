//! Environment variable expansion: `${VAR}` and `${VAR:-default}`, with
//! defaults that may name other variables.

/// Expand `${VAR}` and `${VAR:-default}` patterns in a config string.
///
/// - `${VAR}` is replaced with the environment variable's value, or the empty
///   string if unset/empty.
/// - `${VAR:-fallback}` uses `fallback` when the variable is unset or empty.
///   The fallback may itself hold references, expanded the same way, so one
///   setting can fall back on another: `${A_URL:-redis://${A_HOST:-cache}:6379}`.
///   A variable's value is used as it is, never expanded again.
/// - Text that is no reference (`$5`, `${1X}`, an unclosed `${`) is kept.
///
/// Public so an extension that loads its own config file (the
/// `extensions.<name>` path form) expands it with the same rules as
/// `siphon.yaml`, rather than carrying a copy that can drift.
///
/// ```
/// use siphon::config::expand_env_vars;
///
/// let expanded = expand_env_vars("listen: \"127.0.0.1:${SIPHON_DOC_UNSET_PORT:-8090}\"");
/// assert_eq!(expanded, "listen: \"127.0.0.1:8090\"");
/// ```
pub fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match env_reference(after) {
            Some((name, fallback, consumed)) => {
                match std::env::var(name) {
                    Ok(value) if !value.is_empty() => out.push_str(&value),
                    _ => out.push_str(&expand_env_vars(fallback.unwrap_or_default())),
                }
                rest = &after[consumed..];
            }
            None => {
                out.push_str("${");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The reference that `text` (what follows a `${`) starts with: the variable
/// name, its fallback, and the bytes it takes up to and with its closing
/// brace. A fallback ends at the brace that closes this reference, counting
/// the references inside it. None when `text` starts no reference.
fn env_reference(text: &str) -> Option<(&str, Option<&str>, usize)> {
    let bytes = text.as_bytes();
    let starts_name = |byte: u8| byte == b'_' || byte.is_ascii_alphabetic();
    if !bytes.first().copied().is_some_and(starts_name) {
        return None;
    }
    let name_length = bytes
        .iter()
        .position(|&byte| !(byte == b'_' || byte.is_ascii_alphanumeric()))?;
    let name = &text[..name_length];
    let after_name = &text[name_length..];
    if after_name.starts_with('}') {
        return Some((name, None, name_length + 1));
    }
    let fallback_start = name_length + after_name.strip_prefix(":-").map(|_| 2)?;
    let mut depth = 0usize;
    let mut index = fallback_start;
    while index < bytes.len() {
        if text[index..].starts_with("${") {
            depth += 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'}' {
            if depth == 0 {
                return Some((name, Some(&text[fallback_start..index]), index + 1));
            }
            depth -= 1;
        }
        index += 1;
    }
    None
}
