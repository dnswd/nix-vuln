#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod cpe_match;
pub mod graph_builder;

mod cli;
mod whitelist;
mod cve_db;
mod app;
mod nix_store;
mod scanner;

use clap::Parser;

pub fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    let db_path = std::env::current_dir()?.join("cves.db");
    let mut db = cve_db::CveDatabase::open(&db_path)?;

    if let Some(ingest_path) = cli.ingest {
        let content = std::fs::read_to_string(&ingest_path)?;
        db.ingest_json_feed(&content)?;
        println!("Successfully ingested {}", ingest_path.display());
        if cli.paths.is_empty() && !cli.system && cli.profile.is_none() && !cli.gc_roots {
            return Ok(());
        }
    }

    let whitelist = if let Some(whitelist_path) = cli.whitelist {
        let content = std::fs::read_to_string(&whitelist_path)?;
        if whitelist_path.extension().and_then(|s| s.to_str()) == Some("yaml") || whitelist_path.extension().and_then(|s| s.to_str()) == Some("yml") {
            Some(whitelist::Whitelist::from_yaml(&content)?)
        } else {
            Some(whitelist::Whitelist::from_toml(&content)?)
        }
    } else {
        None
    };

    let mut paths_to_scan = cli.paths;
    if cli.system {
        paths_to_scan.push(std::path::PathBuf::from("/nix/var/nix/gcroots/current-system"));
    }

    if let Some(profile_path) = cli.profile {
        paths_to_scan.push(std::path::PathBuf::from(profile_path));
    }

    if cli.gc_roots {
        paths_to_scan.push(std::path::PathBuf::from("/nix/var/nix/gcroots"));
    }

    if paths_to_scan.is_empty() {
        println!("Warning: No paths or targets provided for scanning.");
    }

    if cli.closure || cli.requisites {
        paths_to_scan = nix_store::resolve_closure(&paths_to_scan)?;
    }

    let app = app::App::new(&db, whitelist.as_ref());
    let graph_data = app.build_graph(&paths_to_scan)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(server::start_server(3000, graph_data))?;

    Ok(())
}

mod server;
