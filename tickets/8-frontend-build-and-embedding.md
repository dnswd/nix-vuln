# Decision: Frontend Build and Embedding

## Context
As decided in ticket 7, we are using Vite for the React frontend and embedding the built assets into the Rust backend using `rust-embed`.

## Problem
We need to set up the repository structure so that standard Rust tooling (`cargo build`) orchestrates the Vite build seamlessly, ensuring `rust-embed` has access to the latest frontend assets.

## Constraints & Considerations
- We shouldn't require users to manually run `npm run build` before `cargo build`.
- We could use a `build.rs` script to invoke `npm install` and `npm run build` if the frontend `dist` directory is missing or outdated.
- Alternatively, we require developers to use `nix` to handle the build orchestration. 
- How does `cargo` caching interact with frontend asset changes?

## Output
A working build configuration that seamlessly compiles the React frontend and embeds it into the Rust binary.
## Resolution
- We will use a `build.rs` script at the root of the backend to orchestrate the frontend build.
- `build.rs` will use `std::process::Command` to invoke `npm install` and `npm run build` inside the `frontend` directory.
- This ensures that `cargo build` automatically builds the frontend assets.
- We will use the `rust-embed` crate in the Rust application to embed the contents of `frontend/dist` into the final binary.
- Cargo caching will be configured to rebuild if the `frontend` directory changes by adding `cargo:rerun-if-changed=frontend/src`, `cargo:rerun-if-changed=frontend/package.json`, etc. in `build.rs`.
- Status: Resolved.