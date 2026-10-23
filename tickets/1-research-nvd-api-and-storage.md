Status: Closed

# Research NVD API & Storage

The original `vulnix` fetched CVE feeds using the legacy NIST JSON 2.0 feeds and cached them using Python's ZODB (Zope Object Database). 

## Tasks
1. **NVD API Update**: NIST deprecated their JSON feeds in late 2023. We must investigate whether to use the NVD REST API 2.0 or an alternative community mirror/source for bulk CVE downloading.
2. **Embedded Database**: Evaluate an embedded database for Rust to replace ZODB. Candidates include:
   - `sqlite` (via `rusqlite` or `sqlx`)
   - `sled` (native Rust KV store)
   - `redb` (native Rust KV store)
3. **Schema Design**: Design a schema that allows fast lookup by the `product` name, mirroring the `by_product` index in the original Python code.

## Resolution
1. **NVD API Update**: We will use the **`nix-community/nvd-cve-feeds`** community mirror. The official NVD REST API 2.0 has strict rate limiting (requiring API keys to be usable) and pagination that makes cold-start syncing for offline use cumbersome. Using daily bulk JSON snapshots from the community mirror enables simple, offline-friendly caching.
2. **Embedded Database**: We will use **`redb`**. It is a pure-Rust, fast, and memory-mapped key-value store. It fits perfectly since `vulnix` primarily does basic KV lookups (`Product -> [CVEs]`) without needing complex SQL queries, and avoiding `rusqlite` keeps the toolchain pure Rust without C-dependencies.
3. **Schema Design**: `redb` will contain a primary table mapping `&str` (the product name) to `&[u8]` (a serialized format, like bincode or JSON, of a list of `Vulnerability` records). This provides an instant `by_product` lookup equivalent to the original ZODB OOBTree index.
