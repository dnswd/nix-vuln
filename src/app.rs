#![deny(clippy::all, clippy::pedantic)]
#![allow(dead_code)]

use anyhow::Result;
use std::path::PathBuf;
use crate::cve_db::CveDatabase;
use crate::whitelist::Whitelist;

pub struct App<'a> {
    pub db: &'a CveDatabase,
    pub whitelist: Option<&'a Whitelist>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ScanResult {
    pub pname: String,
    pub version: String,
    pub cves: Vec<String>,
}

impl<'a> App<'a> {
    pub fn new(db: &'a CveDatabase, whitelist: Option<&'a Whitelist>) -> Self {
        Self { db, whitelist }
    }
    #[allow(clippy::unnecessary_wraps)]
    pub fn scan_paths(&self, paths: &[PathBuf]) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();

        for path in paths {
            let info = match crate::nix_store::parse_derivation(path) {
                Ok(i) => i,
                Err(e) => {
                    println!("Failed to parse: {e}");
                    continue;
                }
            };

            if let Ok(candidates) = self.db.query_by_product(&info.pname)
                && !candidates.is_empty()
            {
                    let scanner = crate::scanner::Scanner::new(self.whitelist);
                    let matched_cves = scanner.match_vulnerabilities(&info.pname, &info.version, &candidates);
                    if !matched_cves.is_empty() {
                        results.push(ScanResult {
                            pname: info.pname,
                            version: info.version,
                            cves: matched_cves,
                        });
                    }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_scan_paths() -> Result<()> {
        let dir = tempdir()?;
        let db_path = dir.path().join("cves.db");
        let mut db = CveDatabase::open(&db_path)?;

        let nvd_json = r#"{
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": { "ID": "CVE-2023-1234" }
                    },
                    "configurations": {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpe_match": [
                                    {
                                        "vulnerable": true,
                                        "cpe23Uri": "cpe:2.3:a:gnu:bash:1.0:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }"#;

        db.ingest_json_feed(nvd_json)?;

        let drv_path = dir.path().join("bash-1.0.drv");
        // Derivation with pname bash and version 1.0
        fs::write(&drv_path, r#"Derive([("out","/nix/store/11111111111111111111111111111111-bash-1.0","","")],[],[],"x86_64-linux","/nix/store/11111111111111111111111111111111-builder.sh",[],[("name","bash-1.0"),("out","/nix/store/11111111111111111111111111111111-bash-1.0")])"#)?;

        let app = App::new(&db, None);
        let result = app.scan_paths(&[drv_path])?;

        assert_eq!(result, vec![
            ScanResult {
                pname: "bash".into(),
                version: "1.0".into(),
                cves: vec!["CVE-2023-1234".into()],
            }
        ]);

        Ok(())
    }
}
