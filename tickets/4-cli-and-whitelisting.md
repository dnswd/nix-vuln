Status: Closed

# CLI and Whitelisting

The tool needs to emulate the original `vulnix` command-line flags and its flexible whitelisting system.

## Tasks
1. **CLI Scaffolding**: Setup `clap` to handle the required flags:
   - `-S, --system`: Scan current system (`/nix/var/nix/gcroots/current-system`)
   - `-p, --profile`: Scan specific profile
   - `--gc-roots`: Scan live GC roots
   - `-r, --requisites` / `-C, --closure` for store paths.
2. **Whitelist Parsing**: The Python tool supports reading whitelist files formatted in either TOML or YAML.
   - Implement a parser combining `serde_json` / `toml` / `serde_yaml` to deserialize suppression rules.
   - Support rule types: exact package name and version matches, partial matches, or specific CVE exclusions.

## Resolution

Integrated `clap` to handle CLI arguments (`paths`, `--whitelist`, `-S`, `-p`, `--gc-roots`, `-r`, `-C`).
Added `serde`, `toml`, and `serde_yaml` to support parsing whitelists.
Created `src/cli.rs` and `src/whitelist.rs` with custom deserialization for handling both single and multiple CVE string entries.
