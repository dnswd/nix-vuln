#![deny(clippy::all, clippy::pedantic)]
#![allow(dead_code)]

use anyhow::Result;
use std::path::PathBuf;
use crate::cve_db::CveDatabase;
use crate::whitelist::Whitelist;
use crate::graph_builder::GraphData;

pub struct App<'a> {
    pub db: &'a CveDatabase,
    pub whitelist: Option<&'a Whitelist>,
}

impl<'a> App<'a> {
    pub fn new(db: &'a CveDatabase, whitelist: Option<&'a Whitelist>) -> Self {
        Self { db, whitelist }
    }

    pub fn build_graph(&self, paths: &[PathBuf]) -> Result<GraphData> {
        let mut derivations = std::collections::HashMap::new();
        let mut vulnerabilities = std::collections::HashMap::new();

        for path in paths {
            let Ok(info) = crate::nix_store::parse_derivation(path) else {
                continue;
            };

            let pname = info.pname.clone();
            let version = info.version.clone();
            derivations.insert(path.clone(), info);

            if let Ok(candidates) = self.db.query_by_product(&pname)
                && !candidates.is_empty()
            {
                    let scanner = crate::scanner::Scanner::new(self.whitelist);
                    let matched = scanner.match_vulnerabilities(&pname, &version, &candidates);
                    if !matched.is_empty() {
                        vulnerabilities.insert(path.clone(), matched);
                    }
            }
        }

        if paths.is_empty() {
            anyhow::bail!("paths cannot be empty");
        }

        let root = paths.last().unwrap();
        let graph = crate::graph_builder::build_graph(root, &derivations, &vulnerabilities);
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;


    #[test]
    fn test_build_graph() -> Result<()> {
        let dir = tempdir()?;
        let db_path = dir.path().join("cves2.db");
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
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH"
                            }
                        }
                    }
                }
            ]
        }"#;

        db.ingest_json_feed(nvd_json)?;

        let drv_path = dir.path().join("bash-1.0.drv");
        fs::write(&drv_path, r#"Derive([("out","/nix/store/11111111111111111111111111111111-bash-1.0","","")],[],[],"x86_64-linux","/nix/store/11111111111111111111111111111111-builder.sh",[],[("name","bash-1.0"),("out","/nix/store/11111111111111111111111111111111-bash-1.0")])"#)?;

        let app = App::new(&db, None);
        let graph = app.build_graph(&[drv_path])?;

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].color, "DarkRed");

        Ok(())
    }

}
