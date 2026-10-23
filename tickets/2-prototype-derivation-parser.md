- Status: Closed

# Prototype Derivation Parser

The original `vulnix` Python codebase parses `.drv` files by loading them and executing them as Python code using `eval()`, exploiting the fact that the `.drv` syntax is somewhat valid Python.

## Tasks
1. **Identify Rust Crate**: Investigate the `nix-derivation` Rust crate to see if it supports robust parsing of all derivation fields.
2. **Fallback Parser**: If no crate fits our exact needs perfectly, prototype a safe parsing mechanism for the `Derive(...)` syntax.
3. **Extract `pname` and `version`**: Implement the package name and version splitting logic. In Python, this was done using the regex `^(\S+?)-([0-9]\S*)$`.

## Resolution

The `nix-derivation` crate works perfectly for our needs. We can load a `.drv` file, parse it with `Derivation::from_aterm_bytes()`, and read the `name` from the derivation's `environment()` map. 

We implemented the regex `^(\S+?)-([0-9]\S*)$` which successfully splits the derivation name into `pname` and `version` (e.g., `bash-interactive-5.2p37` -> `bash-interactive` and `5.2p37`).
