use crate::nix_store::DerivationInfo;
use crate::cve_db::CveRecord;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Clone)]
pub struct GraphData {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Clone)]
pub struct Node {
    pub id: String,
    pub label: String,
    pub color: String,
    pub cves: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Clone)]
pub struct Link {
    pub source: String,
    pub target: String,
}

use std::collections::HashSet;

fn get_severity_weight(sev: Option<&str>) -> u8 {
    match sev {
        Some("CRITICAL") => 4,
        Some("MEDIUM") => 2,
        Some("LOW") => 1,
        Some(_) | None => 3,
    }
}

fn severity_to_color(sev: Option<&str>, has_transitive: bool) -> String {
    match sev {
        Some("CRITICAL") => "BrightRed".to_string(),
        Some("MEDIUM") => "DarkOrange".to_string(),
        Some("LOW") => "DarkYellow".to_string(),
        Some(_) => "DarkRed".to_string(),
        None => {
            if has_transitive {
                "Gray".to_string()
            } else {
                "White".to_string()
            }
        }
    }
}

struct TraversalState<'a, S> {
    derivations: &'a HashMap<PathBuf, DerivationInfo, S>,
    vulnerabilities: &'a HashMap<PathBuf, Vec<CveRecord>, S>,
    visited: HashSet<PathBuf>,
    nodes: HashMap<PathBuf, Node>,
    links: HashSet<(PathBuf, PathBuf)>,
    risk_cache: HashMap<PathBuf, (Option<String>, bool)>,
}

impl<S: std::hash::BuildHasher> TraversalState<'_, S> {
    fn compute_risk(&mut self, path: &PathBuf) -> (Option<String>, bool) {
        if let Some(cached) = self.risk_cache.get(path) {
            return cached.clone();
        }

        self.risk_cache.insert(path.clone(), (None, false));

        let cves = self.vulnerabilities.get(path).map_or(&[] as &[CveRecord], std::vec::Vec::as_slice);
        let mut max_sev: Option<String> = None;
        let mut max_weight = 0;
        
        for cve in cves {
            let sev = cve.cvss_severity.as_deref();
            let weight = get_severity_weight(sev.or(Some("UNKNOWN")));
            if weight > max_weight {
                max_weight = weight;
                max_sev = sev.map(ToString::to_string).or(Some("UNKNOWN".to_string()));
            }
        }

        let mut has_transitive = false;
        if let Some(info) = self.derivations.get(path) {
            let edges = info.edges.clone();
            for edge in edges {
                let (child_sev, child_transitive) = self.compute_risk(&edge);
                if child_sev.is_some() || child_transitive {
                    has_transitive = true;
                }
            }
        }

        let result = (max_sev, has_transitive);
        self.risk_cache.insert(path.clone(), result.clone());
        result
    }

    fn traverse(&mut self, path: &PathBuf) {
        if self.visited.contains(path) {
            return;
        }
        self.visited.insert(path.clone());

        let Some(info) = self.derivations.get(path) else {
            return;
        };

        let edges = info.edges.clone();
        for edge in &edges {
            self.links.insert((path.clone(), edge.clone()));
            self.traverse(edge);
        }

        let (max_sev, has_transitive) = self.compute_risk(path);
        
        let cves: Vec<String> = self.vulnerabilities.get(path)
            .map(|c| c.iter().map(|rec| rec.id.clone()).collect())
            .unwrap_or_default();

        let label = format!("{}-{}", info.pname, info.version);
        let color = severity_to_color(max_sev.as_deref(), has_transitive);

        self.nodes.insert(path.clone(), Node {
            id: path.to_string_lossy().to_string(),
            label,
            color,
            cves,
        });
    }
}

#[must_use]
pub fn build_graph<S: std::hash::BuildHasher>(
    root: &PathBuf,
    derivations: &HashMap<PathBuf, DerivationInfo, S>,
    vulnerabilities: &HashMap<PathBuf, Vec<CveRecord>, S>,
) -> GraphData {
    let mut state = TraversalState {
        derivations,
        vulnerabilities,
        visited: HashSet::new(),
        nodes: HashMap::new(),
        links: HashSet::new(),
        risk_cache: HashMap::new(),
    };

    state.traverse(root);

    let nodes: Vec<Node> = state.nodes.into_values().collect();
    let links: Vec<Link> = state.links.into_iter().map(|(src, tgt)| Link {
        source: src.to_string_lossy().to_string(),
        target: tgt.to_string_lossy().to_string(),
    }).collect();

    GraphData { nodes, links }
 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_graph_transitive_risk() {
        let parent_path = PathBuf::from("/nix/store/parent.drv");
        let child_path = PathBuf::from("/nix/store/child.drv");

        let mut derivations = HashMap::new();
        derivations.insert(
            parent_path.clone(),
            DerivationInfo {
                pname: "parent".to_string(),
                version: "1.0".to_string(),
                drv_path: parent_path.clone(),
                edges: vec![child_path.clone()],
            }
        );
        derivations.insert(
            child_path.clone(),
            DerivationInfo {
                pname: "child".to_string(),
                version: "2.0".to_string(),
                drv_path: child_path.clone(),
                edges: vec![],
            }
        );

        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            child_path.clone(),
            vec![CveRecord {
                id: "CVE-2023-1234".to_string(),
                product: "child".to_string(),
                versions: vec!["2.0".to_string()],
                cvss_score: Some(7.5),
                cvss_severity: Some("HIGH".to_string()),
            }]
        );

        let graph = build_graph(&parent_path, &derivations, &vulnerabilities);

        assert_eq!(graph.nodes.len(), 2);
        
        let child_node = graph.nodes.iter().find(|n| n.id == child_path.to_string_lossy().to_string()).unwrap();
        assert_eq!(child_node.color, "DarkRed");
        
        let parent_node = graph.nodes.iter().find(|n| n.id == parent_path.to_string_lossy().to_string()).unwrap();
        assert_eq!(parent_node.color, "Gray");

        assert_eq!(graph.links.len(), 1);
        assert_eq!(graph.links[0].source, parent_path.to_string_lossy().to_string());
        assert_eq!(graph.links[0].target, child_path.to_string_lossy().to_string());
    }
}
