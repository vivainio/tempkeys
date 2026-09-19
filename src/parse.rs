//! Parsing a keyset from stdin: a JSON object of strings, or dotenv-style lines.

use crate::sys::Secret;

/// Names must be usable as environment variable names.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn parse_keyset(input: &str) -> Result<Vec<(String, Secret)>, String> {
    let entries = if input.trim_start().starts_with('{') {
        parse_json(input)?
    } else {
        parse_env(input)?
    };
    let mut seen = std::collections::HashSet::new();
    for (name, value) in &entries {
        if !valid_name(name) {
            return Err(format!(
                "invalid key name {name:?} (use letters, digits, underscore)"
            ));
        }
        if value.0.is_empty() {
            return Err(format!(
                "{name}: empty values are not supported by kernel user keys"
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(format!("duplicate key {name}"));
        }
    }
    if entries.is_empty() {
        return Err("keyset is empty".into());
    }
    Ok(entries)
}

fn parse_json(input: &str) -> Result<Vec<(String, Secret)>, String> {
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("bad JSON: {e}"))?;
    let obj = value.as_object().ok_or("JSON keyset must be an object")?;
    obj.iter()
        .map(|(k, v)| match v {
            serde_json::Value::String(s) => Ok((k.clone(), Secret(s.clone().into_bytes()))),
            _ => Err(format!("{k}: JSON values must be strings")),
        })
        .collect()
}

fn parse_env(input: &str) -> Result<Vec<(String, Secret)>, String> {
    let mut out = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected KEY=VALUE", i + 1))?;
        out.push((
            name.trim().to_string(),
            Secret(unquote(value.trim()).into_bytes()),
        ));
    }
    Ok(out)
}

/// Strip one pair of matching surrounding quotes. Values are otherwise literal:
/// no escapes or interpolation.
fn unquote(v: &str) -> String {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(input: &str) -> Vec<(String, String)> {
        parse_keyset(input)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8(v.0.clone()).unwrap()))
            .collect()
    }

    #[test]
    fn dotenv() {
        let got = names("# c\nA=1\nexport B=\"two words\"\n\nC='x=y'\n");
        assert_eq!(
            got,
            [("A", "1"), ("B", "two words"), ("C", "x=y")]
                .map(|(k, v)| (k.to_string(), v.to_string()))
        );
    }

    #[test]
    fn json() {
        assert_eq!(
            names(r#"{"A":"1"}"#),
            vec![("A".to_string(), "1".to_string())]
        );
        assert!(parse_keyset(r#"{"A":1}"#).is_err());
    }

    #[test]
    fn rejects() {
        assert!(parse_keyset("A=1\nA=2").is_err());
        assert!(parse_keyset("1A=x").is_err());
        assert!(parse_keyset("A=").is_err());
        assert!(parse_keyset("# only a comment").is_err());
    }
}
