#![deny(clippy::all, clippy::pedantic)]
#![allow(dead_code)]

use anyhow::Context;
use anyhow::Result;
use nix_derivation::Derivation;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static NAME_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\S+?)-([0-9]\S*)$").expect("Regex should compile"));

#[must_use]
pub fn split_name_version(name: &str) -> (&str, &str) {
    if let Some(caps) = NAME_VERSION_RE.captures(name) {
        let pname = caps.get(1).map_or(name, |m| m.as_str());
        let version = caps.get(2).map_or("", |m| m.as_str());
        (pname, version)
    } else {
        (name, "")
    }
}

pub fn extract_derivation_name(content: &[u8]) -> Result<String> {
    let drv = Derivation::from_aterm_bytes(content, "drv")
        .map_err(|e| anyhow::anyhow!("Failed to parse derivation: {e:?}"))?;

    let name_bytes = drv.environment().get("name").with_context(|| {
        let drv_path = drv
            .drv_path()
            .map_or_else(|e| format!("<unavailable: {e}>"), |p| p.to_string());
        format!("Derivation {drv_path} has no 'name' environment variable")
    })?;

    Ok(String::from_utf8_lossy(name_bytes).into_owned())
}

#[derive(Debug, PartialEq, Eq)]
pub struct DerivationInfo {
    pub pname: String,
    pub version: String,
    pub drv_path: PathBuf,
    pub edges: Vec<PathBuf>,
}

pub fn parse_derivation(path: &Path) -> Result<DerivationInfo> {
    let content =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let drv = Derivation::from_aterm_bytes(&content, "drv")
        .map_err(|e| anyhow::anyhow!("Failed to parse derivation at {}: {e:?}", path.display()))?;

    let name = drv.environment().get("name").map_or_else(
        || {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        },
        |b| String::from_utf8_lossy(b).into_owned(),
    );

    let (pname, version) = split_name_version(&name);

    let edges: Vec<PathBuf> = drv
        .input_derivations()
        .keys()
        .map(|k| PathBuf::from(k.to_string()))
        .collect();

    Ok(DerivationInfo {
        pname: pname.to_string(),
        version: version.to_string(),
        drv_path: path.to_path_buf(),
        edges,
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn resolve_closure(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if paths.is_empty() {
        return Ok(vec![]);
    }

    let mut cmd = std::process::Command::new("nix-store");
    cmd.arg("-qR");
    for p in paths {
        cmd.arg(p);
    }

    let output = cmd.output().context("Failed to execute nix-store")?;

    if !output.status.success() {
        anyhow::bail!(
            "nix-store -qR failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8(output.stdout)?;
    let resolved_paths = stdout
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();

    Ok(resolved_paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    #[test]
    fn test_parse_derivation() -> Result<()> {
        let temp_dir = env::temp_dir();
        let drv_path = temp_dir.join("bash-5.2-p15.drv");

        let drv_content = r#"Derive([("out","/nix/store/h1r2ndz03m00ww054r7d6s9g3p7b1d1f-bash-5.2-p15","","")],[],[],"x86_64-linux","/nix/store/k133k922r0szidk3a8fmdy1fhwf41b4s-builder.sh",[],[("name","bash-5.2-p15"),("out","/nix/store/h1r2ndz03m00ww054r7d6s9g3p7b1d1f-bash-5.2-p15")])"#;

        fs::write(&drv_path, drv_content)?;

        let result = parse_derivation(&drv_path);

        assert_eq!(
            result.unwrap(),
            DerivationInfo {
                pname: "bash".to_string(),
                version: "5.2-p15".to_string(),
                drv_path: drv_path.clone(),
                edges: vec![],
            }
        );

        fs::remove_file(drv_path)?;
        Ok(())
    }

    #[test]
    fn test_split_name_version() {
        assert_eq!(split_name_version("bash-5.2-p15"), ("bash", "5.2-p15"));
        assert_eq!(split_name_version("openssl-1.1.1u"), ("openssl", "1.1.1u"));
        assert_eq!(
            split_name_version("some-package-name-with-dashes-1.2.3"),
            ("some-package-name-with-dashes", "1.2.3")
        );

        // No version
        assert_eq!(split_name_version("just-a-name"), ("just-a-name", ""));

        // Edge cases
        assert_eq!(split_name_version("pkg-0"), ("pkg", "0"));
        assert_eq!(split_name_version("pkg-0.1"), ("pkg", "0.1"));
        assert_eq!(split_name_version("a-1"), ("a", "1"));
        assert_eq!(
            split_name_version("invalidversion-"),
            ("invalidversion-", "")
        );
    }

    #[test]
    fn test_extract_derivation_name_valid() {
        let valid_drv = r#"Derive([("out","/nix/store/11111111111111111111111111111111-out","","")],[],[],"x86_64-linux","/nix/store/22222222222222222222222222222222-builder.sh",[],[("builder","/nix/store/22222222222222222222222222222222-builder.sh"),("name","valid-pkg-1.2.3"),("out","/nix/store/11111111111111111111111111111111-out"),("system","x86_64-linux")])"#;
        let name =
            extract_derivation_name(valid_drv.as_bytes()).expect("Should parse valid derivation");
        assert_eq!(name, "valid-pkg-1.2.3");
    }

    #[test]
    fn test_extract_derivation_name_missing_name() {
        let no_name_drv = r#"Derive([("out","/nix/store/11111111111111111111111111111111-out","","")],[],[],"x86_64-linux","/nix/store/22222222222222222222222222222222-builder.sh",[],[("builder","/nix/store/22222222222222222222222222222222-builder.sh"),("out","/nix/store/11111111111111111111111111111111-out"),("system","x86_64-linux")])"#;
        let err = extract_derivation_name(no_name_drv.as_bytes()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Derivation has no 'name' environment variable"
        );
    }

    #[test]
    fn test_resolve_closure() -> Result<()> {
        use std::process::Command;
        let output = Command::new("nix-instantiate")
            .args(["-E", "(import <nixpkgs> {}).hello"])
            .output()
            .context("Failed to run nix-instantiate")?;

        assert!(
            output.status.success(),
            "nix-instantiate failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let drv_path_str = String::from_utf8(output.stdout)?.trim().to_string();
        let drv_path = PathBuf::from(drv_path_str);

        let closure = resolve_closure(&[drv_path])?;
        assert!(!closure.is_empty(), "Closure should not be empty");

        Ok(())
    }

    #[test]
    fn test_extract_derivation_name_invalid_parsing() {
        let invalid_drv = b"Not a valid aterm derivation string";
        let err = extract_derivation_name(invalid_drv).unwrap_err();
        assert!(err.to_string().starts_with("Failed to parse derivation:"));
    }
}
