use std::process::Command;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/index.html");
    println!("cargo:rerun-if-changed=frontend/vite.config.ts");
    println!("cargo:rerun-if-changed=frontend/package.json");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let frontend_dir = PathBuf::from(&manifest_dir).join("frontend");

    // Skip building frontend if we're just checking
    if env::var("PROFILE").unwrap_or_default() == "rls" || env::var("RUSTC_WRAPPER").unwrap_or_default().contains("rust-analyzer") {
        return;
    }

    if env::var("SKIP_NPM_BUILD").unwrap_or_default() == "1" {
        return;
    }

    let status = Command::new("npm")
        .arg("install")
        .current_dir(&frontend_dir)
        .status()
        .expect("Failed to run npm install");
    
    if !status.success() {
        panic!("npm install failed");
    }

    let status = Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(&frontend_dir)
        .status()
        .expect("Failed to run npm run build");
        
    if !status.success() {
        panic!("npm run build failed");
    }
}
