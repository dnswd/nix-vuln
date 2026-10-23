#![deny(clippy::all, clippy::pedantic)]

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, PartialEq, Eq)]
#[command(author, version, about, long_about = None)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Paths to derivations or nix store paths to scan
    #[arg(num_args = 0..)]
    pub paths: Vec<PathBuf>,

    /// Path to a whitelist file (TOML or YAML)
    #[arg(short = 'W', long)]
    pub whitelist: Option<PathBuf>,

    /// Scan current system (/nix/var/nix/gcroots/current-system)
    #[arg(short = 'S', long)]
    pub system: bool,

    /// Scan specific profile
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Scan live GC roots
    #[arg(long)]
    pub gc_roots: bool,

    /// Scan requisites (store paths)
    #[arg(short, long)]
    pub requisites: bool,

    /// Scan closure (store paths)
    #[arg(short = 'C', long)]
    pub closure: bool,

    /// Ingest a JSON feed into the database
    #[arg(long)]
    pub ingest: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn test_cli_parsing_basic() {
        let args = vec!["vulnix", "/nix/store/xxxx-some-pkg.drv"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.paths, vec![PathBuf::from("/nix/store/xxxx-some-pkg.drv")]);
        assert_eq!(cli.whitelist, None);
    }

    #[test]
    fn test_cli_parsing_with_whitelist() {
        let args = vec!["vulnix", "--whitelist", "my-whitelist.toml", "/nix/store/xxxx-some-pkg.drv"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.paths, vec![PathBuf::from("/nix/store/xxxx-some-pkg.drv")]);
        assert_eq!(cli.whitelist, Some(PathBuf::from("my-whitelist.toml")));
    }

    #[test]
    fn test_cli_multiple_paths() {
        let args: Vec<OsString> = vec![
            "vulnix".into(),
            "/path/one.drv".into(),
            "/path/two.drv".into(),
        ];
        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.paths,
            vec![PathBuf::from("/path/one.drv"), PathBuf::from("/path/two.drv")]
        );
    }

    #[test]
    fn test_cli_flags() {
        let args = vec!["vulnix", "-S", "--gc-roots", "-C"];
        let cli = Cli::parse_from(args);
        assert!(cli.system);
        assert!(cli.gc_roots);
        assert!(cli.closure);
        assert!(!cli.requisites);
    }
}
