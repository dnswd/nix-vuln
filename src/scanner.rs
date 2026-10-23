#![deny(clippy::all, clippy::pedantic)]
#![allow(dead_code)]

use crate::whitelist::Whitelist;
use crate::cve_db::CveRecord;

pub struct Scanner<'a> {
    pub whitelist: Option<&'a Whitelist>,
}

impl<'a> Scanner<'a> {
    pub fn new(whitelist: Option<&'a Whitelist>) -> Self {
        Self { whitelist }
    }

    #[must_use]
    pub fn match_vulnerabilities(
        &self,
        pname: &str,
        version: &str,
        candidates: &[CveRecord],
    ) -> Vec<String> {
        let mut matched = Vec::new();

        for candidate in candidates {
            let is_match = if candidate.versions.is_empty() {
                true
            } else {
                candidate.versions.iter().any(|v| {
                    if v.starts_with('<') || v.starts_with('>') || v.starts_with('=') {
                        crate::cpe_match::in_range(version, v).unwrap_or(false)
                    } else {
                        crate::cpe_match::cpe_versions_equal(version, v)
                    }
                })
            };

            if is_match {
                let mut whitelisted = false;
                if let Some(whitelist) = self.whitelist {
                    for entry in &whitelist.entries {
                        let cve_match = entry.cve.contains(&candidate.id);
                        let pname_match = entry.pname.as_deref().is_none_or(|p| p == pname);
                        let version_match = entry.version.as_deref().is_none_or(|v| v == version);

                        if cve_match && pname_match && version_match {
                            whitelisted = true;
                            break;
                        }
                    }
                }

                if !whitelisted {
                    matched.push(candidate.id.clone());
                }
            }
        }

        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whitelist::{WhitelistEntry, Whitelist};
    use crate::cve_db::CveRecord;

    #[test]
    fn test_scanner_match_vulnerability() {
        let scanner = Scanner::new(None);
        let candidates = vec![
            CveRecord {
                id: "CVE-2023-1234".to_string(),
                product: "bash".to_string(),
                versions: vec!["1.0".to_string()],
            }
        ];
        
        let matched = scanner.match_vulnerabilities("bash", "1.0", &candidates);
        assert_eq!(matched, vec!["CVE-2023-1234".to_string()]);
    }

    #[test]
    fn test_scanner_whitelist_ignore() {
        let entry = WhitelistEntry {
            cve: vec!["CVE-2023-1234".to_string()],
            pname: Some("bash".to_string()),
            version: Some("1.0".to_string()),
            comment: None,
            issue_url: None,
        };
        let whitelist = Whitelist {
            entries: vec![entry],
        };
        
        let scanner = Scanner::new(Some(&whitelist));
        let candidates = vec![
            CveRecord {
                id: "CVE-2023-1234".to_string(),
                product: "bash".to_string(),
                versions: vec!["1.0".to_string()],
            }
        ];
        
        let matched = scanner.match_vulnerabilities("bash", "1.0", &candidates);
        assert!(matched.is_empty(), "Should be empty, but got {:?}", matched);
    }
}
