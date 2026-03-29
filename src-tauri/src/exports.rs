use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet::PacketRecord;

#[derive(Debug, Clone, Copy)]
pub enum PacketExportFormat {
    Csv,
    Json,
}

impl PacketExportFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

pub fn parse_export_format(value: &str) -> Result<PacketExportFormat, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "csv" => Ok(PacketExportFormat::Csv),
        "json" => Ok(PacketExportFormat::Json),
        other => Err(format!("Format d'export non supporté: {other}")),
    }
}

pub fn build_default_export_path(prefix: &str, extension: &str) -> PathBuf {
    let folder = default_export_folder();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    folder.join(format!("{prefix}-{timestamp}.{extension}"))
}

pub fn export_packets(packets: &[PacketRecord], format: PacketExportFormat) -> Result<String, String> {
    let path = build_default_export_path("wireflux-packets", format.extension());
    ensure_parent_directory(&path)?;

    match format {
        PacketExportFormat::Csv => write_packets_csv(&path, packets)?,
        PacketExportFormat::Json => write_packets_json(&path, packets)?,
    }

    Ok(path.to_string_lossy().to_string())
}

fn default_export_folder() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join("Downloads");
    }
    std::env::temp_dir()
}

pub fn ensure_parent_directory(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .map_err(|error| format!("Impossible de créer le dossier d'export {}: {error}", parent.display()))
}

fn write_packets_json(path: &Path, packets: &[PacketRecord]) -> Result<(), String> {
    let content = serde_json::to_string_pretty(packets)
        .map_err(|error| format!("Impossible de sérialiser le JSON: {error}"))?;
    fs::write(path, content).map_err(|error| format!("Impossible d'écrire {}: {error}", path.display()))
}

fn write_packets_csv(path: &Path, packets: &[PacketRecord]) -> Result<(), String> {
    let mut out = String::new();
    out.push_str("id,timestamp,source,source_mac,source_port,destination,destination_mac,destination_port,protocol,ip_version,ttl_or_hop_limit,tcp_flags,ethertype,length,info,raw_hex\n");

    for packet in packets {
        let row = [
            packet.id.to_string(),
            packet.timestamp.clone(),
            packet.source.clone(),
            packet.source_mac.clone(),
            packet.source_port.map(|value| value.to_string()).unwrap_or_default(),
            packet.destination.clone(),
            packet.destination_mac.clone(),
            packet
                .destination_port
                .map(|value| value.to_string())
                .unwrap_or_default(),
            packet.protocol.clone(),
            packet.ip_version.clone(),
            packet
                .ttl_or_hop_limit
                .map(|value| value.to_string())
                .unwrap_or_default(),
            packet.tcp_flags.clone().unwrap_or_default(),
            packet.ethertype.clone(),
            packet.length.to_string(),
            packet.info.clone(),
            packet.raw_hex.clone(),
        ];
        out.push_str(
            &row.iter()
                .map(|field| csv_escape(field))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }

    fs::write(path, out).map_err(|error| format!("Impossible d'écrire {}: {error}", path.display()))
}

fn csv_escape(value: &str) -> String {
    let needs_quotes = value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');
    if !needs_quotes {
        return value.to_string();
    }
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}
