//! `Link` headers (RFC 8288 section 3), which point to the alternate chains of a certificate.

use reqwest::header::{HeaderMap, LINK};
use url::Url;

/// Limit for the alternate chains fetched per certificate, since each costs a signed request.
const MAX_ALTERNATE_CHAINS: usize = 8;

/// The whitespace between the parts of a link value, `OWS` and `BWS` in RFC 7230.
const WHITESPACE: [char; 2] = [' ', '\t'];

/// One link of a `Link` header.
#[derive(Debug)]
struct Link<'a> {
    /// The target URI reference, between `<` and `>`.
    target: &'a str,
    /// The parameters in order, with unquoted values, empty for a parameter without one.
    params: Vec<(&'a str, String)>,
}

impl Link<'_> {
    /// Returns the value of the first parameter named `name`.
    ///
    /// RFC 8288 section 3.3 has parsers ignore all but the first `rel`.
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(param, _)| param.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns whether this link points to an alternate of the response it came with.
    ///
    /// A link with an `anchor` describes another resource, see RFC 8288 section 3.2.
    fn is_alternate(&self) -> bool {
        let is_alternate = self.param("rel").is_some_and(|rel| {
            rel.split_ascii_whitespace()
                .any(|rel| rel.eq_ignore_ascii_case("alternate"))
        });
        is_alternate && self.param("anchor").is_none()
    }
}

/// Returns the URLs of the alternate chains that the `Link` headers in `headers` point to.
///
/// See RFC 8555 section 7.4.2. Relative URLs are resolved against `base`, the URL of the
/// response. Only `https` URLs are kept, without duplicates and at most
/// [`MAX_ALTERNATE_CHAINS`].
pub(crate) fn alternate_urls(base: &str, headers: &HeaderMap) -> Vec<String> {
    let base = Url::parse(base).ok();
    let targets = headers
        .get_all(LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(parse_links)
        .filter(Link::is_alternate)
        .filter_map(|link| match &base {
            Some(base) => base.join(link.target).ok(),
            None => Url::parse(link.target).ok(),
        })
        .filter(|url| url.scheme() == "https");
    let mut urls: Vec<String> = Vec::new();
    for url in targets {
        if urls.len() == MAX_ALTERNATE_CHAINS {
            break;
        }
        let url = String::from(url);
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

/// Parses the links of the `Link` header value `value`.
///
/// Parsing stops at the first malformed link, and returns the links before it.
fn parse_links(value: &str) -> Vec<Link<'_>> {
    let mut links = Vec::new();
    let mut rest = value;
    loop {
        rest = rest.trim_start_matches(|c| WHITESPACE.contains(&c) || c == ',');
        if rest.is_empty() {
            return links;
        }
        let Some((link, after)) = parse_link(rest) else {
            return links;
        };
        links.push(link);
        rest = after;
    }
}

/// Parses the link at the start of `s`, and returns it and the rest of `s`.
///
/// Returns `None` unless the link ends at a comma or the end of `s`.
fn parse_link(s: &str) -> Option<(Link<'_>, &str)> {
    let (target, mut rest) = s.strip_prefix('<')?.split_once('>')?;
    let mut params = Vec::new();
    while let Some(after) = rest.trim_start_matches(WHITESPACE).strip_prefix(';') {
        let (name, after) = token(after.trim_start_matches(WHITESPACE));
        if name.is_empty() {
            return None;
        }
        rest = after.trim_start_matches(WHITESPACE);
        let value = match rest.strip_prefix('=') {
            Some(after) => {
                let after = after.trim_start_matches(WHITESPACE);
                let (value, after) = match after.strip_prefix('"') {
                    Some(quoted) => quoted_string(quoted)?,
                    None => {
                        let (value, after) = token(after);
                        (value.to_owned(), after)
                    }
                };
                rest = after;
                value
            }
            None => String::new(),
        };
        params.push((name, value));
    }
    let rest = rest.trim_start_matches(WHITESPACE);
    (rest.is_empty() || rest.starts_with(',')).then_some((Link { target, params }, rest))
}

/// Splits the token at the start of `s` from the rest, see `token` in RFC 7230 section 3.2.6.
fn token(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)))
        .unwrap_or(s.len());
    s.split_at(end)
}

/// Parses a quoted string after its opening quote, and returns its value and the rest.
///
/// A backslash quotes the character after it, see `quoted-pair` in RFC 7230 section 3.2.6.
fn quoted_string(s: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((value, &s[i + 1..])),
            '\\' => value.push(chars.next()?.1),
            c => value.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    /// The URL of the certificate whose `Link` headers the tests parse.
    const BASE: &str = "https://ca.example/acme/cert/1";

    /// Returns the alternate URLs of the `Link` headers `values`.
    fn alternates(values: &[&str]) -> Vec<String> {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(LINK, HeaderValue::from_str(value).expect("valid header"));
        }
        alternate_urls(BASE, &headers)
    }

    #[test]
    fn finds_alternates_in_rfc8288_link_values() {
        assert_eq!(
            alternates(&[
                // Boulder's format, one link per header.
                r#"<https://ca.example/up>;rel="up""#,
                r#"<https://ca.example/a>;rel="alternate""#,
                // Several links in one header, unquoted and spaced params,
                // case-insensitive names, multi-valued rel, a comma in a URL.
                r#"<https://ca.example/up>; rel="up", <https://ca.example/b,1>; REL=alternate"#,
                r#"<https://ca.example/c> ; title="x;y" ; rel = "index alternate""#,
                // Quoted commas and escaped quotes don't end a link, and escapes are removed.
                concat!(
                    r#"<https://ca.example/d>; title="a, \"b\"; c"; rel="alternate", "#,
                    r#"<https://ca.example/e>; rel="\alternate""#,
                ),
                // A parameter without a value, and a relative URL.
                r#"<f>; crossorigin; rel="alternate""#,
            ]),
            [
                "https://ca.example/a",
                "https://ca.example/b,1",
                "https://ca.example/c",
                "https://ca.example/d",
                "https://ca.example/e",
                "https://ca.example/acme/cert/f",
            ],
        );
    }

    #[test]
    fn keeps_https_urls_once_up_to_the_cap() {
        let mut values = vec![
            r#"<http://ca.example/plain>;rel="alternate""#.to_string(),
            r#"<https://ca.example/a>;rel="alternate""#.to_string(),
            r#"<https://ca.example/a>;rel="alternate""#.to_string(),
        ];
        values.extend((0..20).map(|i| format!(r#"<https://ca.example/n/{i}>;rel="alternate""#)));
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        let urls = alternates(&values);
        assert_eq!(urls.len(), MAX_ALTERNATE_CHAINS);
        assert_eq!(
            urls[..2],
            ["https://ca.example/a", "https://ca.example/n/0"]
        );
    }

    #[test]
    fn ignores_other_relations_and_contexts() {
        assert!(
            alternates(&[
                r#"<https://ca.example/up>;rel="up""#,
                r#"<https://ca.example/c>;rel="alternates""#,
                // Only the first rel counts.
                r#"<https://ca.example/d>;rel="up";rel="alternate""#,
                // The link is about another resource.
                r#"<https://ca.example/e>;rel="alternate";anchor="https://ca.example/other""#,
            ])
            .is_empty()
        );
    }

    #[test]
    fn stops_at_a_malformed_link() {
        assert_eq!(
            alternates(&[
                r#"https://no-brackets.example;rel="alternate""#,
                concat!(
                    r#"<https://ca.example/a>;rel="alternate", "#,
                    r#"<https://ca.example/b>;rel="alternate"x, "#,
                    r#"<https://ca.example/c>;rel="alternate""#,
                ),
                r#"<https://ca.example/d>;rel="alternate"; title="unterminated"#,
                r#"<https://ca.example/e>;="alternate""#,
            ]),
            ["https://ca.example/a"],
        );
    }
}
