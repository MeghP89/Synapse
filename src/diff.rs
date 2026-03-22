use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct ScanSnapshot {
    pub target: String,
    pub timestamp: u64,
    pub hosts: Vec<HostSnapshot>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HostSnapshot {
    pub ip: String,
    pub hostname: String,
    pub ports: HashMap<u16, String>,
}

pub struct PortChange {
    pub ip: String,
    pub port: u16,
    pub from: String,
    pub to: String,
}

pub struct DiffResult {
    pub new_hosts: Vec<String>,
    pub lost_hosts: Vec<String>,
    pub port_changes: Vec<PortChange>,
}

pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn save_snapshot(snapshot: &ScanSnapshot) -> std::io::Result<()> {
    fs::create_dir_all("results")?;
    let path = format!("results/synapse_{}_{}.json", sanitize(&snapshot.target), snapshot.timestamp);
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(path, json)
}

pub fn load_latest_snapshot(target: &str) -> Option<ScanSnapshot> {
    let prefix = format!("synapse_{}_", sanitize(target));
    let mut entries: Vec<_> = fs::read_dir("results").ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy().to_string();
            name.starts_with(&prefix) && name.ends_with(".json")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());
    let content = fs::read_to_string(entries.last()?.path()).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn compute_diff(old: &ScanSnapshot, new: &ScanSnapshot) -> DiffResult {
    let old_map: HashMap<&str, &HostSnapshot> = old.hosts.iter().map(|h| (h.ip.as_str(), h)).collect();
    let new_map: HashMap<&str, &HostSnapshot> = new.hosts.iter().map(|h| (h.ip.as_str(), h)).collect();

    let new_hosts = new.hosts.iter()
        .filter(|h| !old_map.contains_key(h.ip.as_str()))
        .map(|h| h.ip.clone())
        .collect();

    let lost_hosts = old.hosts.iter()
        .filter(|h| !new_map.contains_key(h.ip.as_str()))
        .map(|h| h.ip.clone())
        .collect();

    let mut port_changes = Vec::new();
    for new_host in &new.hosts {
        if let Some(old_host) = old_map.get(new_host.ip.as_str()) {
            let all_ports: HashSet<u16> = old_host.ports.keys()
                .chain(new_host.ports.keys())
                .copied()
                .collect();
            for port in all_ports {
                let from = old_host.ports.get(&port).map(String::as_str).unwrap_or("absent");
                let to   = new_host.ports.get(&port).map(String::as_str).unwrap_or("absent");
                if from != to {
                    port_changes.push(PortChange {
                        ip: new_host.ip.clone(),
                        port,
                        from: from.to_string(),
                        to: to.to_string(),
                    });
                }
            }
        }
    }

    DiffResult { new_hosts, lost_hosts, port_changes }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}
