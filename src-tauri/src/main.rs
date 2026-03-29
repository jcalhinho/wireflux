#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ai;
mod capture;
mod exports;
mod packet;

use std::sync::Mutex;

use capture::{list_interfaces as list_capture_interfaces, CaptureManager};
use packet::PacketRecord;
use tauri::State;

#[derive(Default)]
struct AppState {
    capture: Mutex<CaptureManager>,
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<String>, String> {
    list_capture_interfaces()
}

#[tauri::command]
fn start_capture(
    interface: String,
    app: tauri::AppHandle,
    state: State<AppState>,
) -> Result<(), String> {
    let mut manager = state
        .capture
        .lock()
        .map_err(|_| "Mutex capture indisponible".to_string())?;
    manager.start_capture(interface, app)
}

#[tauri::command]
fn stop_capture(state: State<AppState>) -> Result<(), String> {
    let mut manager = state
        .capture
        .lock()
        .map_err(|_| "Mutex capture indisponible".to_string())?;
    manager.stop_capture();
    Ok(())
}

#[tauri::command]
async fn explain_packet(packet: PacketRecord, model: Option<String>) -> Result<String, String> {
    ai::explain_packet(packet, model).await
}

#[tauri::command]
async fn explain_packet_stream(
    packet: PacketRecord,
    model: Option<String>,
    request_id: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    ai::explain_packet_stream(app, packet, model, request_id).await
}

#[tauri::command]
async fn ai_status() -> Result<ai::AiHealthStatus, String> {
    Ok(ai::ai_status().await)
}

#[tauri::command]
fn export_pcap(state: State<AppState>) -> Result<String, String> {
    let manager = state
        .capture
        .lock()
        .map_err(|_| "Mutex capture indisponible".to_string())?;
    manager.export_pcap()
}

#[tauri::command]
fn export_packets(packets: Vec<PacketRecord>, format: String) -> Result<String, String> {
    let parsed_format = exports::parse_export_format(&format)?;
    exports::export_packets(&packets, parsed_format)
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            stop_capture,
            explain_packet,
            explain_packet_stream,
            ai_status,
            export_pcap,
            export_packets
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
