#![deny(clippy::all, clippy::pedantic)]
#![allow(dead_code)]

use serde::{de, Deserialize, Deserializer};
use std::fmt;

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct WhitelistEntry {
    pub pname: Option<String>,
    pub version: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub cve: Vec<String>,
    pub issue_url: Option<String>,
    pub comment: Option<String>,
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = seq.next_element()? {
                vec.push(elem);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum WhitelistFormat {
    Map {
        #[serde(alias = "whitelist")]
        entries: Vec<WhitelistEntry>,
    },
    List(Vec<WhitelistEntry>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Whitelist {
    pub entries: Vec<WhitelistEntry>,
}

impl Whitelist {
    /// Parse a whitelist from TOML string.
    ///
    /// # Errors
    /// Returns an error if the TOML format is invalid or missing the required fields.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        let format: WhitelistFormat = toml::from_str(content)?;
        match format {
            WhitelistFormat::Map { entries } | WhitelistFormat::List(entries) => Ok(Self { entries }),
        }
    }

    /// Parse a whitelist from YAML string.
    ///
    /// # Errors
    /// Returns an error if the YAML format is invalid or missing the required fields.
    pub fn from_yaml(content: &str) -> Result<Self, serde_yaml::Error> {
        let format: WhitelistFormat = serde_yaml::from_str(content)?;
        match format {
            WhitelistFormat::Map { entries } | WhitelistFormat::List(entries) => Ok(Self { entries }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_toml() {
        let toml_str = r#"
        [[whitelist]]
        pname = "libxslt"
        version = "1.1.34"
        cve = "CVE-2015-7995"
        comment = "Already patched"

        [[whitelist]]
        pname = "foo"
        cve = ["CVE-2020-1234", "CVE-2021-5678"]
        "#;

        let whitelist = Whitelist::from_toml(toml_str).unwrap();
        assert_eq!(whitelist.entries.len(), 2);
        assert_eq!(whitelist.entries[0].pname.as_deref(), Some("libxslt"));
        assert_eq!(whitelist.entries[0].cve, vec!["CVE-2015-7995"]);
        assert_eq!(whitelist.entries[1].cve, vec!["CVE-2020-1234", "CVE-2021-5678"]);
    }

    #[test]
    fn test_deserialize_yaml() {
        let yaml_str = r#"
- pname: "libxslt"
  version: "1.1.34"
  cve: "CVE-2015-7995"
  comment: "Already patched"
- pname: "foo"
  cve: 
    - "CVE-2020-1234"
    - "CVE-2021-5678"
"#;

        let whitelist = Whitelist::from_yaml(yaml_str).unwrap();
        assert_eq!(whitelist.entries.len(), 2);
        assert_eq!(whitelist.entries[0].pname.as_deref(), Some("libxslt"));
        assert_eq!(whitelist.entries[0].cve, vec!["CVE-2015-7995"]);
        assert_eq!(whitelist.entries[1].cve, vec!["CVE-2020-1234", "CVE-2021-5678"]);
    }
}
