# Decision: How to extract derivation edges

## Context
Currently, our vulnerability scanner relies on `nix-store -qR` to fetch the requisite closure paths for a derivation, which gives us a flat list of dependencies. To support the new graph-based web UI, we need the actual directed edges between derivations to accurately represent the dependency tree.

## Problem
We need to extract the dependency edges (parent -> child) of Nix derivations to build the graph, similar to what `nix-tree` does.

## Constraints & Considerations
- We currently have `src/nix_store.rs` doing a flat list lookup.
- We could invoke `nix-store -q --graph` or parse `.drv` files directly to construct the edges.
- Alternatively, we might use `nix-tree` as a data source or replicate its logic using `nix-derivation` to parse input derivations and their references.

## Output
A strategy for efficiently extracting and representing derivation relationships (edges) for the frontend graph renderer.

## Resolution
The most efficient and robust approach is to parse the `.drv` files directly using the `nix-derivation` crate.

1. The `nix-derivation::Derivation` struct exposes an `input_drvs` field (typically a `BTreeMap` or `HashMap`), which contains the exact store paths of the input derivations (dependencies) that the current derivation depends on.
2. By iterating through a derivation's `input_drvs`, we can construct a list of `parent -> child` edges without having to shell out to `nix-store -q --graph` or write a custom DOT language parser.
3. The process would start with the root derivation(s), read and parse their `.drv` files, and recursively traverse through the `input_drvs`, collecting nodes and edges along the way.

This pure Rust approach avoids relying on external CLI tools like `nix-tree` or complex string parsing of command outputs, providing a reliable and performant way to build the data structure for the frontend graph renderer.
