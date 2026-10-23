# Wayfinder Map: Vulnix Rust Web UI

## Destination
A web-based UI with a force-directed graph (using `react-force-graph`) that visualizes the Nix derivation dependency tree. The graph nodes represent packages and are color-coded based on their NVD CVSS vulnerability scores, allowing users to interactively inspect dependencies, identify transitive risks, and view mitigation steps.

## Notes & Domain Information
- **Web Architecture**: We need a web backend (such as `axum`, `actix-web`, or a simpler embedded HTTP server) combined with a frontend (HTML/JS/`react-force-graph`). The goal is to provide a seamless "instant inspect" experience (e.g., via `nix flake run`).
- **CVSS Parsing**: NVD data must be parsed for CVSS metrics to determine the severity of vulnerabilities. Currently, `cve_db` does not store CVSS data, which is essential for the node color-coding requirements (e.g., White for safe, Bright red for critical).
- **Derivation Edges**: To visualize the tree structure (similar to `nix-tree`), we need actual directed dependency edges. Currently, the tool uses `nix-store -qR`, which only produces a flat list of dependencies. A mechanism for parsing derivation linkages is required.

## Decisions so far
- **No `eval()`**: The Rust port uses a proper parser or `nix-derivation`.
- **Database & Data Source**: Using `redb` as the pure-Rust embedded KV store and community CVE feeds.
- [1-research-nvd-api-and-storage.md](tickets/1-research-nvd-api-and-storage.md): Use `redb` and community CVE feeds.
- [2-prototype-derivation-parser.md](tickets/2-prototype-derivation-parser.md): Use `nix-derivation` crate and regex for pname/version splitting.
- [3-implement-cpe-matching.md](tickets/3-implement-cpe-matching.md): Implemented `cpe_match.rs` mimicking Python's `compare_cpe_versions`.
- [4-cli-and-whitelisting.md](tickets/4-cli-and-whitelisting.md): Scaffold the `clap` CLI and the TOML/YAML whitelist logic.
- [5-how-to-extract-derivation-edges.md](tickets/5-how-to-extract-derivation-edges.md): Parse `.drv` files with `nix-derivation` and use `input_drvs` to build the dependency graph.
- [6-cvss-storage-and-parsing.md](tickets/6-cvss-storage-and-parsing.md): Update `CveRecord` schema (with `#[serde(default)]`) and define parsing rules for NVD CVSS metrics.

- [7-backend-frontend-architecture.md](tickets/7-backend-frontend-architecture.md): Use `axum` with `rust-embed` for the backend, and Vite/React for the frontend. Separated data endpoints (`/api/graph` and `/api/node/:id`).
- [8-frontend-build-and-embedding.md](tickets/8-frontend-build-and-embedding.md): Use `build.rs` to orchestrate `npm install` and `npm run build`, and `rust-embed` to serve the resulting `dist` folder.
- [9-graph-ux-and-interaction.md](tickets/9-graph-ux-and-interaction.md): Frontend UX includes a "Hide Safe Nodes" toggle. Nodes are colored by CVSS severity (White=Safe, Gray=Transitive Risk, Dark yellow=Low, Dark orange=Medium, Dark red=High, Bright red=Critical). Clicking a node shows CVE details, CVSS scores, mitigations, and `nix-versions` alternative links.

## Frontier

### Open Tickets
None.

### Not yet specified
