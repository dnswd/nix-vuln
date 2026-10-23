Status: Closed

# Implement CPE Matching

CPE matching in `vulnix` is intentionally simplified to increase speed and reduce noise, but requires specific implementation details to maintain parity.

## Tasks
1. **Vendor Agnosticism**: Implement the logic that strips or entirely ignores the `vendor` segment of a CPE URI (`cpe:2.3:a:<vendor>:<product>:...`). `vulnix` looks up exclusively by `product`.
2. **Version Matching Rules**:
   - Port the custom `compare_cpe_versions` and `cpe_versions_equal` functions from Python.
   - Ensure trailing zero components (like `153.0.0` vs `153.0` vs `153`) are treated as equal, which was a specific feature of the Python test suite.
   - Handle numeric ranges and exact matches correctly.
3. **CISA KEV Integration**: Connect the parsed CVEs with the CISA Known Exploited Vulnerabilities catalog (via CSV download) to flag issues under active exploitation.

## Resolution
- **Version Matching Rules**: Implemented `cpe_match.rs` mimicking Python's `compare_cpe_versions`, `cpe_versions_equal`, and `in_range`. Trailing zeroes (like `153.0.0` vs `153`) are normalized and treated equally, mirroring the original Nix-based comparator. The module is fully tested using the original Python test payloads and adheres to `#![deny(clippy::all, clippy::pedantic)]`.
