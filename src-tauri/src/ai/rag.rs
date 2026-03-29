use crate::packet::PacketRecord;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const MAX_EVIDENCE: usize = 3;
const MIN_RELEVANCE_SCORE: i32 = 4;

#[derive(Debug, Clone)]
pub struct RagContext {
    pub prompt_block: String,
    pub evidence_count: usize,
    pub corpus_label: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RagChunkRaw {
    chunk_id: String,
    doc_id: String,
    source_id: String,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    section: String,
    content: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    osi_layers: Vec<u8>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(default)]
    confidence_level: String,
}

#[derive(Debug, Clone)]
struct RagChunk {
    chunk_id: String,
    doc_id: String,
    source_id: String,
    source_url: String,
    title: String,
    section: String,
    content: String,
    tags: Vec<String>,
    osi_layers: Vec<u8>,
    ports: Vec<u16>,
    protocols: Vec<String>,
    confidence_level: String,
    tokens: HashSet<String>,
    tier_weight: i32,
}

#[derive(Debug, Clone, Deserialize)]
struct SourceCatalog {
    #[serde(default)]
    sources: Vec<SourceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct SourceEntry {
    id: String,
    #[serde(default)]
    tier: String,
}

#[derive(Debug, Clone)]
struct ScoredChunk<'a> {
    chunk: &'a RagChunk,
    score: i32,
}

#[derive(Debug, Default)]
struct RagIndex {
    chunks: Vec<RagChunk>,
    corpus_path: Option<PathBuf>,
}

static RAG_INDEX: OnceLock<RagIndex> = OnceLock::new();

pub fn build_rag_context(packet: &PacketRecord) -> Option<RagContext> {
    let index = RAG_INDEX.get_or_init(load_rag_index);
    if index.chunks.is_empty() {
        return None;
    }

    let query_tokens = query_tokens_from_packet(packet);
    let mut scored: Vec<ScoredChunk<'_>> = index
        .chunks
        .iter()
        .map(|chunk| ScoredChunk {
            score: score_chunk(packet, &query_tokens, chunk),
            chunk,
        })
        .filter(|entry| entry.score >= MIN_RELEVANCE_SCORE)
        .collect();

    if scored.is_empty() {
        return None;
    }

    scored.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.chunk.tier_weight.cmp(&a.chunk.tier_weight))
            .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
    });

    let selected: Vec<ScoredChunk<'_>> = scored.into_iter().take(MAX_EVIDENCE).collect();
    if selected.is_empty() {
        return None;
    }

    let checks = build_verification_checks(packet, &selected);
    let mut evidence_lines = Vec::new();
    for (index, entry) in selected.iter().enumerate() {
        let snippet = compact_text(&entry.chunk.content, 220);
        let section = if entry.chunk.section.is_empty() {
            "section:n/a".to_string()
        } else {
            format!("section:{}", entry.chunk.section)
        };
        let confidence = if entry.chunk.confidence_level.is_empty() {
            "confidence:n/a".to_string()
        } else {
            format!("confidence:{}", entry.chunk.confidence_level)
        };
        let source_url = if entry.chunk.source_url.is_empty() {
            "url:n/a".to_string()
        } else {
            format!("url:{}", entry.chunk.source_url)
        };
        evidence_lines.push(format!(
            "E{} | ref={}/{} | {} | {} | {} | {} | {}",
            index + 1,
            entry.chunk.source_id,
            entry.chunk.doc_id,
            if entry.chunk.title.is_empty() {
                "untitled"
            } else {
                entry.chunk.title.as_str()
            },
            section,
            confidence,
            source_url,
            snippet
        ));
    }

    let mut prompt_block = String::new();
    prompt_block.push_str("RAG policy (obligatoire):\n");
    prompt_block.push_str("- Evidence-first: appuie-toi d'abord sur les preuves ci-dessous.\n");
    prompt_block.push_str("- Citation stricte: cite `ref=source_id/doc_id` pour chaque affirmation clé.\n");
    prompt_block.push_str("- Si la preuve manque: écris explicitement `preuve insuffisante`.\n");

    if !checks.is_empty() {
        prompt_block.push_str("\nVérifications concrètes à traiter:\n");
        for check in &checks {
            prompt_block.push_str("- ");
            prompt_block.push_str(check);
            prompt_block.push('\n');
        }
    }

    prompt_block.push_str("\nPreuves récupérées:\n");
    for line in &evidence_lines {
        prompt_block.push_str("- ");
        prompt_block.push_str(line);
        prompt_block.push('\n');
    }

    let corpus_label = index
        .corpus_path
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("corpus local")
        .to_string();

    Some(RagContext {
        prompt_block,
        evidence_count: selected.len(),
        corpus_label,
    })
}

fn build_verification_checks(packet: &PacketRecord, selected: &[ScoredChunk<'_>]) -> Vec<String> {
    let mut checks = Vec::new();

    let eth = packet.ethertype.trim().to_ascii_uppercase();
    let l3 = packet.ip_version.trim().to_ascii_uppercase();
    let eth_l3_check = match (eth.as_str(), l3.as_str()) {
        ("0X0800", "IPV4") => "Cohérence L2/L3: EtherType 0x0800 cohérent avec IPv4.",
        ("0X86DD", "IPV6") => "Cohérence L2/L3: EtherType 0x86DD cohérent avec IPv6.",
        ("0X0806", "ARP") => "Cohérence L2/L3: EtherType 0x0806 cohérent avec ARP.",
        _ if l3.starts_with("IPV") => {
            "Cohérence L2/L3: EtherType et version IP non alignés, vérifier capture/parsing."
        }
        _ => "Cohérence L2/L3: non applicable (protocole non-IP ou inconnu).",
    };
    checks.push(eth_l3_check.to_string());

    let main_port = packet.destination_port.or(packet.source_port);
    if let Some(port) = main_port {
        if let Some(reference) = first_reference_for_port(selected, port) {
            checks.push(format!(
                "Port/service: port {port} observé, référence trouvée ({reference})."
            ));
        } else {
            checks.push(format!(
                "Port/service: port {port} observé mais sans preuve directe dans le corpus local."
            ));
        }
    } else {
        checks.push("Port/service: ports absents dans ce paquet (normal pour certains protocoles).".to_string());
    }

    let protocol = packet.protocol.trim().to_ascii_uppercase();
    let has_tcp_flags = packet
        .tcp_flags
        .as_deref()
        .map(|flags| !flags.trim().is_empty() && flags.trim() != "-")
        .unwrap_or(false);
    if protocol == "TCP" {
        if has_tcp_flags {
            checks.push("Transport: flags TCP présents, utiliser l'état SYN/ACK/FIN/RST pour la phase de session."
                .to_string());
        } else {
            checks.push("Transport: protocole TCP sans flags exploitables, préciser la limite de preuve."
                .to_string());
        }
    } else if has_tcp_flags {
        checks.push("Transport: flags TCP reçus alors que le protocole n'est pas TCP, incohérence à signaler."
            .to_string());
    } else {
        checks.push("Transport: pas de flags TCP attendus pour ce protocole (UDP/ICMP/etc.).".to_string());
    }

    let ttl_message = match packet.ttl_or_hop_limit {
        Some(0) => "TTL/Hop: valeur 0, paquet en fin de vie (souvent message de contrôle).".to_string(),
        Some(value) if value < 16 => {
            format!("TTL/Hop: {value}, valeur faible indiquant un routage intermédiaire long.")
        }
        Some(value) => format!("TTL/Hop: {value}, valeur exploitable pour contexte de trajet."),
        None => "TTL/Hop: non disponible pour ce paquet.".to_string(),
    };
    checks.push(ttl_message);

    let is_udp_443 = protocol == "UDP"
        && (packet.source_port == Some(443) || packet.destination_port == Some(443));
    if is_udp_443 {
        if let Some(reference) = first_reference_containing(selected, "quic") {
            checks.push(format!(
                "UDP/443: hypothèse QUIC plausible avec preuve locale ({reference}); confirmer via flux/session."
            ));
        } else {
            checks.push(
                "UDP/443: hypothèse QUIC possible mais preuve locale insuffisante sur ce paquet seul."
                    .to_string(),
            );
        }
    }

    checks
}

fn first_reference_for_port(selected: &[ScoredChunk<'_>], port: u16) -> Option<String> {
    selected
        .iter()
        .find(|entry| entry.chunk.ports.contains(&port))
        .map(|entry| format!("{}/{}", entry.chunk.source_id, entry.chunk.doc_id))
}

fn first_reference_containing(selected: &[ScoredChunk<'_>], needle: &str) -> Option<String> {
    let needle = needle.to_ascii_lowercase();
    selected
        .iter()
        .find(|entry| {
            entry
                .chunk
                .content
                .to_ascii_lowercase()
                .contains(&needle)
                || entry.chunk.tags.iter().any(|tag| tag.to_ascii_lowercase() == needle)
        })
        .map(|entry| format!("{}/{}", entry.chunk.source_id, entry.chunk.doc_id))
}

fn score_chunk(packet: &PacketRecord, query_tokens: &HashSet<String>, chunk: &RagChunk) -> i32 {
    let mut score = 0;
    let overlap = query_tokens.intersection(&chunk.tokens).count() as i32;
    score += overlap * 2;

    let packet_protocol = packet.protocol.trim().to_ascii_lowercase();
    if !packet_protocol.is_empty() && chunk.protocols.iter().any(|proto| proto == &packet_protocol) {
        score += 6;
    }

    if let Some(source_port) = packet.source_port {
        if chunk.ports.contains(&source_port) {
            score += 8;
        }
    }
    if let Some(destination_port) = packet.destination_port {
        if chunk.ports.contains(&destination_port) {
            score += 8;
        }
    }

    if matches!(packet_protocol.as_str(), "tcp" | "udp") && chunk.osi_layers.contains(&4) {
        score += 2;
    }
    if chunk.osi_layers.contains(&3) {
        score += 1;
    }

    if packet
        .ip_version
        .trim()
        .to_ascii_lowercase()
        .contains("ipv6")
        && chunk.tokens.contains("ipv6")
    {
        score += 2;
    }
    if packet
        .ip_version
        .trim()
        .to_ascii_lowercase()
        .contains("ipv4")
        && chunk.tokens.contains("ipv4")
    {
        score += 2;
    }

    score + chunk.tier_weight
}

fn query_tokens_from_packet(packet: &PacketRecord) -> HashSet<String> {
    let mut parts = Vec::new();
    parts.push(packet.protocol.clone());
    parts.push(packet.ip_version.clone());
    parts.push(packet.info.clone());
    parts.push(packet.ethertype.clone());
    parts.push(packet.raw_hex.clone());
    if let Some(flags) = &packet.tcp_flags {
        parts.push(flags.clone());
    }
    if let Some(source_port) = packet.source_port {
        parts.push(source_port.to_string());
    }
    if let Some(destination_port) = packet.destination_port {
        parts.push(destination_port.to_string());
    }
    tokenize(&parts.join(" "))
}

fn load_rag_index() -> RagIndex {
    let corpus_path = find_existing_path(&corpus_candidates());
    let sources_path = find_existing_path(&sources_candidates());
    let mut chunks = Vec::new();

    let tier_weights = sources_path
        .as_ref()
        .and_then(|path| load_source_tiers(path).ok())
        .unwrap_or_default();

    if let Some(path) = &corpus_path {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let parsed = match serde_json::from_str::<RagChunkRaw>(trimmed) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                let normalized = normalize_chunk(parsed, &tier_weights);
                if normalized.content.is_empty() {
                    continue;
                }
                chunks.push(normalized);
            }
        }
    }

    RagIndex { chunks, corpus_path }
}

fn normalize_chunk(raw: RagChunkRaw, tiers: &HashMap<String, i32>) -> RagChunk {
    let protocols = raw
        .protocols
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let tier_weight = tiers.get(&raw.source_id).copied().unwrap_or(0);

    let token_text = format!(
        "{} {} {} {} {} {}",
        raw.title,
        raw.section,
        raw.content,
        raw.tags.join(" "),
        protocols.join(" "),
        raw.ports
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );

    RagChunk {
        chunk_id: raw.chunk_id,
        doc_id: raw.doc_id,
        source_id: raw.source_id,
        source_url: raw.source_url,
        title: raw.title,
        section: raw.section,
        content: raw.content.trim().to_string(),
        tags: raw.tags,
        osi_layers: raw.osi_layers,
        ports: raw.ports,
        protocols,
        confidence_level: raw.confidence_level,
        tokens: tokenize(&token_text),
        tier_weight,
    }
}

fn load_source_tiers(path: &Path) -> Result<HashMap<String, i32>, String> {
    let content = fs::read_to_string(path).map_err(|error| format!("read sources.json: {error}"))?;
    let catalog: SourceCatalog =
        serde_json::from_str(&content).map_err(|error| format!("parse sources.json: {error}"))?;

    let mut tiers = HashMap::new();
    for source in catalog.sources {
        let weight = match source.tier.trim().to_ascii_lowercase().as_str() {
            "tier-1-normative" => 3,
            "tier-2-security-knowledge" => 2,
            "tier-3-supporting" => 1,
            _ => 0,
        };
        tiers.insert(source.id, weight);
    }
    Ok(tiers)
}

fn corpus_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("WIREFLUX_RAG_CORPUS_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    candidates.push(PathBuf::from("public/docs/rag/wireflux-reference-corpus.jsonl"));
    candidates.push(PathBuf::from("../public/docs/rag/wireflux-reference-corpus.jsonl"));
    candidates.push(PathBuf::from("../../public/docs/rag/wireflux-reference-corpus.jsonl"));
    candidates.push(PathBuf::from("dist/docs/rag/wireflux-reference-corpus.jsonl"));
    candidates.push(PathBuf::from("../dist/docs/rag/wireflux-reference-corpus.jsonl"));

    candidates.push(PathBuf::from("public/docs/rag/example-wireflux-corpus.jsonl"));
    candidates.push(PathBuf::from("../public/docs/rag/example-wireflux-corpus.jsonl"));
    candidates.push(PathBuf::from("../../public/docs/rag/example-wireflux-corpus.jsonl"));
    candidates.push(PathBuf::from("dist/docs/rag/example-wireflux-corpus.jsonl"));
    candidates.push(PathBuf::from("../dist/docs/rag/example-wireflux-corpus.jsonl"));
    candidates
}

fn sources_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("WIREFLUX_RAG_SOURCES_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    candidates.push(PathBuf::from("public/docs/rag/sources.json"));
    candidates.push(PathBuf::from("../public/docs/rag/sources.json"));
    candidates.push(PathBuf::from("../../public/docs/rag/sources.json"));
    candidates.push(PathBuf::from("dist/docs/rag/sources.json"));
    candidates.push(PathBuf::from("../dist/docs/rag/sources.json"));
    candidates
}

fn find_existing_path(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.exists()).cloned()
}

fn tokenize(text: &str) -> HashSet<String> {
    let mut tokens = HashSet::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            if current.len() >= 2 {
                tokens.insert(current.clone());
            }
            current.clear();
        }
    }
    if !current.is_empty() && current.len() >= 2 {
        tokens.insert(current);
    }
    tokens
}

fn compact_text(text: &str, max_len: usize) -> String {
    let clean = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.len() <= max_len {
        return clean;
    }
    format!("{}...", &clean[..max_len])
}
