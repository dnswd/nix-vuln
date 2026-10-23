# Decision: Backend and Frontend Architecture

## Context
The project is pivoting from a CLI-only report generator to an interactive graph visualization UI. The user's idea requires a web interface displaying a force-directed graph (using `react-force-graph`) where nodes can be inspected to reveal CVE details, mitigations, and version options.

## Problem
We need an architecture that serves both the API/data requirements of the graph and the static assets of the frontend, all seamlessly bundled for the user.

## Constraints & Considerations
- **Backend**: Should we embed a lightweight web server like `axum` or `actix-web` directly into the CLI tool?
- **Frontend**: Standard HTML/JS or a minimal bundler? We need to integrate `react-force-graph` and ensure the client can easily fetch the generated node and edge data from the backend.
- **Data Delivery**: How will the derivation graph and CVE data be serialized and delivered to the frontend (e.g., a massive JSON payload on load, or dynamically fetched upon node click)?
- The experience should ideally be launchable via a simple command (e.g., `nix flake run`).

## Output
A clear plan for the stack, framework choices, and data contract between the Rust backend and the JavaScript frontend.

## Resolution

### Backend Stack
- **Framework**: Rust with `axum` and `tokio`. It's the standard, performant, and lightweight choice for HTTP APIs in Rust.
- **Asset Serving**: Use `rust-embed` to bake the compiled frontend assets directly into the final Rust binary. This guarantees a single self-contained executable that works seamlessly with `nix flake run` without needing separate asset paths.
- **Startup**: On launch, the backend will parse the local derivation graph, check vulnerabilities, start the `axum` server on `127.0.0.1:3000` (or an available ephemeral port), and print the URL to the terminal (optionally opening the default browser via the `open` crate).

### Frontend Stack
- **Framework**: React with Vite as the bundler. The UI needs state management for node interactions and filtering, and `react-force-graph` integrates best in a React environment.
- **Integration**: The Vite build output (`dist/`) will be included in the Rust binary via `rust-embed` pointing to the build directory.

### Data Contract
To avoid a massive initial load that might freeze the browser, we will split the data delivery:
1. **`GET /api/graph`**: Delivers the lightweight topology and high-level node states.
   - **Response**: `{ "nodes": [{ "id": "drv-hash", "label": "package-name-version", "severity": "critical|high|medium|low|safe", "transitive_risk": true/false }], "links": [{ "source": "drv-hash-1", "target": "drv-hash-2" }] }`
2. **`GET /api/node/:id`**: Fetches detailed CVE information only when a node is clicked.
   - **Response**: List of CVEs, CVSS scores, descriptions, and potential mitigation links (e.g., to `nix-versions`).
