# Decision: CVSS Storage and Parsing

## Context
Our graph UI requires nodes to be color-coded based on the CVSS severity rating (e.g., White for safe, Dark red for high CVSS, Bright red for critical). Currently, our `cve_db` and data ingestion do not parse or store CVSS score data.

## Problem
We must parse, extract, and store CVSS scores from the NVD JSON data so that the scanner can surface this information for the UI to use in node coloring.

## Constraints & Considerations
- NVD data contains CVSSv2, CVSSv3.0, and CVSSv3.1 data. We should define a clear fallback mechanism or priority (e.g., prefer v3.1 > v3.0 > v2.0).
- `cve_db.rs` and the NVD ingestion process must be updated to capture the base score and severity.
- We need a defined model for exposing these scores and corresponding severity levels alongside the vulnerabilities.

## Output
An updated schema for our `redb` vulnerability storage and a parsing plan for NVD CVSS metrics.

## Resolution

**Schema Update**:
Update `CveRecord` in `src/cve_db.rs` to include CVSS fields. To avoid parsing errors on existing database entries, we should use `#[serde(default)]` for the new fields (or we can rebuild the local `redb` cache from the NVD feed):

```rust
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub product: String,
    pub versions: Vec<String>,
    #[serde(default)]
    pub cvss_score: Option<f32>,
    #[serde(default)]
    pub cvss_severity: Option<String>,
}
```

**Parsing Plan**:
In `ingest_json_feed`, before creating the `CveRecord`, we will extract the CVSS metrics from the JSON feed item:
1. Prefer CVSS v3: Search under `impact.baseMetricV3.cvssV3`. Extract `baseScore` (as `f32`) and `baseSeverity` (as string).
2. Fallback to CVSS v2: Search under `impact.baseMetricV2.cvssV2` for `baseScore`, and `impact.baseMetricV2.severity` for the severity rating.
3. Provide the extracted metrics to the new `cvss_score` and `cvss_severity` fields when constructing the `CveRecord`.

This strategy ensures the scanner has the necessary base score and severity data persisted and available for the graph UI to color-code nodes appropriately.
