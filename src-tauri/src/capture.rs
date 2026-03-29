use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::exports::{build_default_export_path, ensure_parent_directory};
use crate::packet::{decode_packet, PacketRecord};

#[derive(Default)]
pub struct CaptureManager {
    session: Option<CaptureSession>,
    last_capture_path: Option<PathBuf>,
}

struct CaptureSession {
    stop_flag: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    capture_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatusEvent {
    pub state: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug)]
struct PcapTailState {
    offset: u64,
    byte_order: Option<ByteOrder>,
    ts_is_nano: bool,
    next_packet_id: u64,
}

impl Default for PcapTailState {
    fn default() -> Self {
        Self {
            offset: 0,
            byte_order: None,
            ts_is_nano: false,
            next_packet_id: 1,
        }
    }
}

impl CaptureManager {
    pub fn start_capture(&mut self, interface: String, app: AppHandle) -> Result<(), String> {
        if self.session.is_some() {
            return Err("Capture déjà en cours".to_string());
        }

        let capture_path = temp_capture_path(&interface);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);
        let worker_capture_path = capture_path.clone();

        let worker = thread::Builder::new()
            .name("wj-capture-worker".to_string())
            .spawn(move || run_capture_loop(interface, worker_capture_path, app, thread_stop))
            .map_err(|error| format!("Impossible de démarrer le thread capture: {error}"))?;

        self.session = Some(CaptureSession {
            stop_flag,
            worker: Some(worker),
            capture_path,
        });

        Ok(())
    }

    pub fn stop_capture(&mut self) {
        let Some(mut session) = self.session.take() else {
            return;
        };

        session.stop_flag.store(true, Ordering::SeqCst);
        if let Some(worker) = session.worker.take() {
            let _ = worker.join();
        }

        if session.capture_path.exists() {
            self.last_capture_path = Some(session.capture_path);
        }
    }

    pub fn export_pcap(&self) -> Result<String, String> {
        let source_path = self
            .current_capture_path()
            .ok_or_else(|| "Aucun fichier PCAP disponible. Démarre une capture d'abord.".to_string())?;

        let destination = build_default_export_path("wireflux-capture", "pcap");
        ensure_parent_directory(&destination)?;

        fs::copy(&source_path, &destination).map_err(|error| {
            format!(
                "Impossible de copier le PCAP {} -> {}: {error}",
                source_path.display(),
                destination.display()
            )
        })?;

        Ok(destination.to_string_lossy().to_string())
    }

    fn current_capture_path(&self) -> Option<PathBuf> {
        if let Some(session) = self.session.as_ref() {
            if session.capture_path.exists() {
                return Some(session.capture_path.clone());
            }
        }

        self.last_capture_path
            .as_ref()
            .filter(|path| path.exists())
            .cloned()
    }
}

pub fn list_interfaces() -> Result<Vec<String>, String> {
    let output = Command::new("dumpcap")
        .arg("-D")
        .output()
        .map_err(|error| format!("Impossible d'exécuter dumpcap -D: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            "dumpcap -D a échoué".to_string()
        } else {
            stderr
        };
        return Err(message);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some((_, rest)) = trimmed.split_once(". ") else {
            continue;
        };

        let Some(name) = rest.split_whitespace().next() else {
            continue;
        };

        if !name.is_empty() && !interfaces.iter().any(|itf| itf == name) {
            interfaces.push(name.to_string());
        }
    }

    Ok(interfaces)
}

fn run_capture_loop(
    interface: String,
    capture_path: PathBuf,
    app: AppHandle,
    stop_flag: Arc<AtomicBool>,
) {
    emit_status(&app, "running", format!("Capture démarrée sur {interface}"));
    let capture_path_str = capture_path.to_string_lossy().to_string();

    let mut child = match Command::new("dumpcap")
        .arg("-i")
        .arg(&interface)
        .arg("-P")
        .arg("-F")
        .arg("pcap")
        .arg("-w")
        .arg(&capture_path_str)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            emit_status(&app, "error", format!("Échec dumpcap: {error}"));
            emit_status(&app, "idle", "Capture inactive".to_string());
            return;
        }
    };

    let mut tail_state = PcapTailState::default();

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            emit_status(&app, "stopping", "Arrêt capture...".to_string());
            let _ = child.kill();
        }

        match read_new_packets(&capture_path, &mut tail_state, 256) {
            Ok(batch) if !batch.is_empty() => {
                let _ = app.emit("packet-batch", batch);
            }
            Ok(_) => {}
            Err(error) => {
                emit_status(&app, "error", format!("Erreur parsing PCAP: {error}"));
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                if let Ok(final_batch) = read_new_packets(&capture_path, &mut tail_state, 512) {
                    if !final_batch.is_empty() {
                        let _ = app.emit("packet-batch", final_batch);
                    }
                }

                if !status.success() && !stop_flag.load(Ordering::SeqCst) {
                    let stderr = read_child_stderr(&mut child);
                    let message = if stderr.is_empty() {
                        "dumpcap s'est terminé avec erreur".to_string()
                    } else {
                        stderr
                    };
                    emit_status(&app, "error", message);
                }
                break;
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(160));
            }
            Err(error) => {
                emit_status(
                    &app,
                    "error",
                    format!("Erreur état process capture: {error}"),
                );
                break;
            }
        }
    }

    emit_status(&app, "idle", "Capture inactive".to_string());
}

fn emit_status(app: &AppHandle, state: &str, message: String) {
    let event = CaptureStatusEvent {
        state: state.to_string(),
        message,
    };
    let _ = app.emit("capture-status", event);
}

fn temp_capture_path(interface: &str) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let safe_interface = interface
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();

    std::env::temp_dir().join(format!("wj-live-{safe_interface}-{millis}.pcap"))
}

fn read_child_stderr(child: &mut std::process::Child) -> String {
    let mut stderr_text = String::new();
    if let Some(stderr) = child.stderr.as_mut() {
        let _ = stderr.read_to_string(&mut stderr_text);
    }
    stderr_text.trim().to_string()
}

fn read_new_packets(
    path: &Path,
    state: &mut PcapTailState,
    max_packets: usize,
) -> io::Result<Vec<PacketRecord>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };

    let total_len = file.metadata()?.len();
    if total_len <= state.offset {
        return Ok(Vec::new());
    }

    file.seek(SeekFrom::Start(state.offset))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut consumed = 0usize;
    if state.byte_order.is_none() {
        if buffer.len() < 24 {
            return Ok(Vec::new());
        }
        let (order, ts_is_nano) = parse_global_header(&buffer[..24])?;
        state.byte_order = Some(order);
        state.ts_is_nano = ts_is_nano;
        consumed += 24;
    }

    let mut packets = Vec::new();
    let order = state.byte_order.unwrap_or(ByteOrder::Little);

    while consumed + 16 <= buffer.len() && packets.len() < max_packets {
        let ts_sec = read_u32(&buffer[consumed..consumed + 4], order);
        let ts_fraction = read_u32(&buffer[consumed + 4..consumed + 8], order);
        let incl_len = read_u32(&buffer[consumed + 8..consumed + 12], order) as usize;
        let _orig_len = read_u32(&buffer[consumed + 12..consumed + 16], order);

        if consumed + 16 + incl_len > buffer.len() {
            break;
        }

        let payload = &buffer[consumed + 16..consumed + 16 + incl_len];
        let packet = decode_packet(
            state.next_packet_id,
            ts_sec,
            ts_fraction,
            state.ts_is_nano,
            incl_len as u32,
            payload,
        );
        packets.push(packet);

        state.next_packet_id += 1;
        consumed += 16 + incl_len;
    }

    state.offset += consumed as u64;
    Ok(packets)
}

fn parse_global_header(header: &[u8]) -> io::Result<(ByteOrder, bool)> {
    if header.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "En-tête global PCAP incomplet",
        ));
    }

    let magic = [header[0], header[1], header[2], header[3]];
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => Ok((ByteOrder::Little, false)),
        [0xa1, 0xb2, 0xc3, 0xd4] => Ok((ByteOrder::Big, false)),
        [0x4d, 0x3c, 0xb2, 0xa1] => Ok((ByteOrder::Little, true)),
        [0xa1, 0xb2, 0x3c, 0x4d] => Ok((ByteOrder::Big, true)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Magic number PCAP inconnu",
        )),
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match order {
        ByteOrder::Little => u32::from_le_bytes(arr),
        ByteOrder::Big => u32::from_be_bytes(arr),
    }
}
