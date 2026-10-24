# nix-vuln

`nix-vuln` is a high-performance Rust port of [`vulnix`](https://github.com/nix-community/vulnix). It analyzes Nix derivation dependency closures for vulnerabilities using NVD data feeds, helping you navigate the hairball of Nix dependencies with visual clarity.

By parsing `.drv` files safely without relying on Nix `eval`, `nix-vuln` builds a strict, deduplicated dependency graph and calculates transitive risk. It pairs a fast backend powered by `redb` with a powerful interactive web UI.

## Features

- **Interactive Graph UI**: A frontend built with Vite and `react-force-graph-2d` provides progressive reveal of your dependency closure (rendering depth=2 transparent neighbors), allowing you to visually trace vulnerabilities.
- **Zero-Dependency Deployment**: The React frontend is embedded directly into the Rust binary during the build. One standalone executable provides both the scanner and the UI server.
- **Fast Graph Traversal**: Safely parses `.drv` inputs and constructs pure, deduplicated graphs using a fast embedded `redb` database.
- **Transitive Risk Calculation**: Identifies both direct vulnerabilities and highlights upstream risks ("Gray" nodes in the graph) to show how an exploit trickles down to your application.

## Usage Guide

### Prerequisites
- Nix with Flakes enabled.

### 1. Ingesting Data

Before analyzing a derivation, `nix-vuln` needs vulnerability data. You can download the NVD CVE feeds (e.g., from the [nix-community/nvd-cve-feeds](https://github.com/nix-community/nvd-cve-feeds) repository).

```bash
# Using nix run (preferred):
nix run . -- --ingest nvdcve-1.1-*.json

# Or running the compiled binary directly:
./target/release/nix-vuln --ingest nvdcve-1.1-*.json
```

### 2. Running a Scan

Once the vulnerability data is ingested, you can scan a derivation. For example, to scan your current Flake:

```bash
# Using nix run (preferred):
nix run . -- --closure $(nix path-info --derivation .)

# Or running the compiled binary directly:
DRV_PATH=$(nix path-info --derivation .)
./target/release/nix-vuln --closure $DRV_PATH
```

This command analyzes the closure and boots an Axum server on `http://127.0.0.1:3000`. Open this address in your browser to explore the interactive dependency graph and investigate any detected vulnerabilities!

## Contributing

`nix-vuln` uses [`just`](https://github.com/casey/just) as a command runner to automate the development workflow. 

### Onboarding

To get started, make sure you have `just` installed, then run the following onboarding commands:

```bash
# Check that your system has all required dependencies
just doctor

# Set up the environment and install dependencies
just setup
```

### Development Workflow

To start a development environment with integrated hot-reloading for both the Rust backend and the React frontend:

```bash
just dev-backend
just dev-frontend
```

Check the `Justfile` for a complete list.

### Architecture Overview

The codebase is split into several distinct responsibilities:

- **`app.rs`**: Handles application wiring, state management, and coordinates the pipeline.
- **`nix_store.rs`**: Parses `.drv` inputs natively and safely directly from the Nix store, skipping the need for Nix `eval`.
- **`graph_builder.rs`**: Constructs the strict deduplicated pure graph logic, calculates transitive risk factors, and assigns CVSS coloring to nodes.
- **`server.rs`**: The Axum web server layer that provides the API endpoints for the UI and embeds the built Vite/React frontend directly into the final Rust binary.
