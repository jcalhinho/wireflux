use crate::packet::PacketRecord;
use super::rag::RagContext;

pub fn build_prompt(packet: &PacketRecord, rag_context: Option<&RagContext>) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let ttl = packet
        .ttl_or_hop_limit
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let flags = packet.tcp_flags.clone().unwrap_or_else(|| "-".to_string());

    let mut prompt = format!(
        "Réponds UNIQUEMENT avec l'explication finale en français.\nInterdit: afficher ton raisonnement, \"Thinking Process\", étapes internes, checklist, analyse méta.\nFormat attendu (détaillé):\n- Contexte du paquet\n- Interprétation protocolaire (L3/L4)\n- Lecture sécurité/diagnostic\n- Hypothèses plausibles (2 max)\n- Action concrète de vérification\nUtilise des puces courtes et techniques.\n\nTimestamp: {}\nSource: {}:{}\nSource MAC: {}\nDestination: {}:{}\nDestination MAC: {}\nL3: {}\nProtocol: {}\nTTL/Hop: {}\nTCP Flags: {}\nEtherType: {}\nLength: {} bytes\nInfo: {}\nHex preview: {}",
        packet.timestamp,
        packet.source,
        src_port,
        packet.source_mac,
        packet.destination,
        dst_port,
        packet.destination_mac,
        packet.ip_version,
        packet.protocol,
        ttl,
        flags,
        packet.ethertype,
        packet.length,
        packet.info,
        packet.raw_hex,
    );

    if let Some(context) = rag_context {
        prompt.push_str("\n\n");
        prompt.push_str(&context.prompt_block);
    }

    prompt
}

pub fn build_compact_prompt(packet: &PacketRecord, rag_context: Option<&RagContext>) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    let mut prompt = format!(
        "Réponds en français avec l'explication finale uniquement.\nInterdit: Thinking Process / raisonnement.\nFormat: 4 puces courtes.\nSource: {}:{} ({})\nDestination: {}:{} ({})\nL3/Proto: {}/{}\nTaille: {} bytes\nInfo: {}",
        packet.source,
        src_port,
        packet.source_mac,
        packet.destination,
        dst_port,
        packet.destination_mac,
        packet.ip_version,
        packet.protocol,
        packet.length,
        packet.info
    );

    if let Some(context) = rag_context {
        prompt.push_str("\n\nPreuves RAG minimales à respecter:\n");
        prompt.push_str(&context.prompt_block);
    }

    prompt
}

pub fn build_chat_prompt(
    question: &str,
    packet: Option<&PacketRecord>,
    rag_context: Option<&RagContext>,
) -> String {
    let mut prompt = String::from(
        "Réponds en français.\n\
         Réponds UNIQUEMENT avec la réponse finale, jamais le raisonnement interne.\n\
         Structure attendue: réponse claire + action concrète de vérification.\n\
         Si la question porte sur l'hexadécimal, utilise d'abord le champ 'Hex preview' fourni ci-dessous.",
    );

    if let Some(packet) = packet {
        let src_port = packet
            .source_port
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let dst_port = packet
            .destination_port
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let ttl = packet
            .ttl_or_hop_limit
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let flags = packet.tcp_flags.clone().unwrap_or_else(|| "-".to_string());

        prompt.push_str(&format!(
            "\n\nContexte paquet actif:\n\
             Timestamp: {}\n\
             Source: {}:{} ({})\n\
             Destination: {}:{} ({})\n\
             L3/Proto: {}/{}\n\
             EtherType: {}\n\
             TTL/Hop: {}\n\
             Flags TCP: {}\n\
             Taille: {} bytes\n\
             Info: {}\n\
             Hex preview: {}",
            packet.timestamp,
            packet.source,
            src_port,
            packet.source_mac,
            packet.destination,
            dst_port,
            packet.destination_mac,
            packet.ip_version,
            packet.protocol,
            packet.ethertype,
            ttl,
            flags,
            packet.length,
            packet.info,
            packet.raw_hex,
        ));
    }

    if let Some(context) = rag_context {
        prompt.push_str("\n\nContexte RAG:\n");
        prompt.push_str(&context.prompt_block);
    }

    prompt.push_str("\n\nQuestion utilisateur:\n");
    prompt.push_str(question.trim());
    prompt
}

pub fn local_explanation(packet: &PacketRecord) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let ttl = packet
        .ttl_or_hop_limit
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let flags = packet.tcp_flags.clone().unwrap_or_else(|| "-".to_string());

    format!(
        "Type: {} / {}\nTrajet: {}:{} ({}) -> {}:{} ({})\nTaille: {} octets\nTTL/Hop: {}\nFlags TCP: {}\nEtherType: {}\nRésumé: {}\nHex preview: {}",
        packet.ip_version,
        packet.protocol,
        packet.source,
        src_port,
        packet.source_mac,
        packet.destination,
        dst_port,
        packet.destination_mac,
        packet.length,
        ttl,
        flags,
        packet.ethertype,
        packet.info,
        packet.raw_hex,
    )
}
