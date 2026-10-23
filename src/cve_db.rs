#![allow(dead_code)]

use anyhow::Result;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub product: String,
    pub versions: Vec<String>,
    #[serde(default)]
    pub cvss_score: Option<f32>,
    #[serde(default)]
    pub cvss_severity: Option<String>,
}

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("cves_by_product");

pub struct CveDatabase {
    db: Database,
}

impl CveDatabase {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        let write_txn = db.begin_write()?;
        write_txn.open_table(TABLE)?;
        write_txn.commit()?;
        Ok(Self { db })
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn ingest_json_feed(&mut self, feed_json: &str) -> Result<()> {
        let root: Value = serde_json::from_str(feed_json)?;
        let Some(items) = root.get("CVE_Items").and_then(Value::as_array) else {
            return Ok(());
        };

        let mut product_cves: HashMap<String, Vec<CveRecord>> = HashMap::new();

        for item in items {
            let id = item
                .get("cve")
                .and_then(|cve| cve.get("CVE_data_meta"))
                .and_then(|meta| meta.get("ID"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();

            if id.is_empty() {
                continue;
            }

            let cvss_score = item
                .get("impact")
                .and_then(|i| i.get("baseMetricV3"))
                .and_then(|bm| bm.get("cvssV3"))
                .and_then(|cvss| cvss.get("baseScore"))
                .and_then(|s| s.as_f64().map(|f| f as f32));

            let cvss_severity = item
                .get("impact")
                .and_then(|i| i.get("baseMetricV3"))
                .and_then(|bm| bm.get("cvssV3"))
                .and_then(|cvss| cvss.get("baseSeverity"))
                .and_then(|s| s.as_str().map(ToString::to_string));

            let nodes = item
                .get("configurations")
                .and_then(|configs| configs.get("nodes"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            for node in nodes {
                let matches = node
                    .get("cpe_match")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for m in matches {
                    if let Some(cpe) = m.get("cpe23Uri").and_then(Value::as_str) {
                        let parts: Vec<&str> = cpe.split(':').collect();
                        if parts.len() >= 6 {
                            let product = parts[4].to_string();
                            let version = parts[5].to_string();

                            if !product.is_empty() {
                                let records = product_cves.entry(product.clone()).or_default();
                                if let Some(record) = records.iter_mut().find(|r| r.id == id) {
                                    if !record.versions.contains(&version) {
                                        record.versions.push(version);
                                    }
                                } else {
                                    records.push(CveRecord {
                                        id: id.clone(),
                                        product,
                                        versions: vec![version],
                                        cvss_score,
                                        cvss_severity: cvss_severity.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE)?;
            for (product, new_records) in product_cves {
                let mut existing_records: Vec<CveRecord> =
                    if let Some(existing_bytes) = table.get(product.as_str())? {
                        serde_json::from_slice(existing_bytes.value())?
                    } else {
                        vec![]
                    };

                for new_rec in new_records {
                    if let Some(existing_rec) =
                        existing_records.iter_mut().find(|r| r.id == new_rec.id)
                    {
                        for v in new_rec.versions {
                            if !existing_rec.versions.contains(&v) {
                                existing_rec.versions.push(v);
                            }
                        }
                    } else {
                        existing_records.push(new_rec);
                    }
                }

                let serialized = serde_json::to_vec(&existing_records)?;
                table.insert(product.as_str(), serialized.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn query_by_product(&self, product: &str) -> Result<Vec<CveRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE)?;
        if let Some(bytes) = table.get(product)? {
            let records = serde_json::from_slice(bytes.value())?;
            Ok(records)
        } else {
            Ok(vec![])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ingest_and_query() {
        let db_path = PathBuf::from("/tmp/dummy_cve.db");
        let _ = std::fs::remove_file(&db_path);
        let mut db = CveDatabase::open(&db_path).unwrap();

        let mock_feed = r#"{
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": { "ID": "CVE-2023-1234" }
                    },
                    "configurations": {
                        "nodes": [
                            {
                                "cpe_match": [
                                    { "cpe23Uri": "cpe:2.3:a:mock_vendor:mock_product:1.0:*:*:*:*:*:*:*" },
                                    { "cpe23Uri": "cpe:2.3:a:mock_vendor:mock_product:1.1:*:*:*:*:*:*:*" }
                                ]
                            }
                        ]
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    }
                }
            ]
        }"#;

        db.ingest_json_feed(mock_feed).unwrap();

        let records = db.query_by_product("mock_product").unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0],
            CveRecord {
                id: "CVE-2023-1234".to_string(),
                product: "mock_product".to_string(),
                versions: vec!["1.0".to_string(), "1.1".to_string()],
                cvss_score: Some(9.8),
                cvss_severity: Some("CRITICAL".to_string()),
            }
        );
    }
}
