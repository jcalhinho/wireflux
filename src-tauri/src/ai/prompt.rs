use crate::packet::PacketRecord;
use super::rag::RagContext;

fn lang_instruction(lang: &str) -> &'static str {
    if lang == "en" {
        "Respond ONLY in English with the final explanation.\n\
         Forbidden: show reasoning, 'Thinking Process', internal steps, meta-analysis.\n\
         Expected format (detailed):\n\
         - Packet context\n\
         - Protocol interpretation (L3/L4)\n\
         - Security/diagnostic reading\n\
         - Plausible hypotheses (max 2)\n\
         - Concrete verification action\n\
         Use short technical bullet points."
    } else {
        "Réponds UNIQUEMENT avec l'explication finale en français.\n\
         Interdit: afficher ton raisonnement, \"Thinking Process\", étapes internes, checklist, analyse méta.\n\
         Format attendu (détaillé):\n\
         - Contexte du paquet\n\
         - Interprétation protocolaire (L3/L4)\n\
         - Lecture sécurité/diagnostic\n\
         - Hypothèses plausibles (2 max)\n\
         - Action concrète de vérification\n\
         Utilise des puces courtes et techniques."
    }
}

fn lang_compact_instruction(lang: &str) -> &'static str {
    if lang == "en" {
        "Respond in English with the final explanation only.\nForbidden: Thinking Process / reasoning.\nFormat: 4 short bullet points."
    } else {
        "Réponds en français avec l'explication finale uniquement.\nInterdit: Thinking Process / raisonnement.\nFormat: 4 puces courtes."
    }
}

pub fn build_prompt(packet: &PacketRecord, rag_context: Option<&RagContext>, lang: &str) -> String {
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
        "{}\n\nTimestamp: {}\nSource: {}:{}\nSource MAC: {}\nDestination: {}:{}\nDestination MAC: {}\nL3: {}\nProtocol: {}\nTTL/Hop: {}\nTCP Flags: {}\nEtherType: {}\nLength: {} bytes\nInfo: {}\nHex preview: {}",
        lang_instruction(lang),
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

pub fn build_compact_prompt(packet: &PacketRecord, rag_context: Option<&RagContext>, lang: &str) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    let mut prompt = format!(
        "{}\nSource: {}:{} ({})\nDestination: {}:{} ({})\nL3/Proto: {}/{}\nSize: {} bytes\nInfo: {}",
        lang_compact_instruction(lang),
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
        prompt.push_str("\n\nRAG minimal context:\n");
        prompt.push_str(&context.prompt_block);
    }

    prompt
}

pub fn build_chat_prompt(
    question: &str,
    packet: Option<&PacketRecord>,
    rag_context: Option<&RagContext>,
    lang: &str,
) -> String {
    let (scope_restriction, lang_instr) = if lang == "en" {
        (
            "You are an assistant specialized EXCLUSIVELY in cybersecurity and network analysis.\n\
             If the question is not related to cybersecurity, network packet analysis, protocols \
             (TCP/IP, DNS, TLS, HTTP…), cyber attacks, system security or traffic analysis, \
             respond ONLY with: \"I am limited to cybersecurity and network analysis questions.\"\n\
             Respond in English.\n\
             Respond ONLY with the final answer, never show internal reasoning.\n\
             Expected structure: clear answer + concrete verification action.\n\
             If the question is about hexadecimal, use the 'Hex preview' field below first.",
            "Respond in English.",
        )
    } else {
        (
            "Tu es un assistant spécialisé EXCLUSIVEMENT en cybersécurité et analyse réseau.\n\
             Si la question n'est pas liée à la cybersécurité, l'analyse de paquets réseau, les protocoles \
             (TCP/IP, DNS, TLS, HTTP…), les attaques informatiques, la sécurité des systèmes ou l'analyse \
             de trafic, réponds UNIQUEMENT par: \
             \"Je suis limité aux questions de cybersécurité et d'analyse réseau.\"\n\
             Réponds en français.\n\
             Réponds UNIQUEMENT avec la réponse finale, jamais le raisonnement interne.\n\
             Structure attendue: réponse claire + action concrète de vérification.\n\
             Si la question porte sur l'hexadécimal, utilise d'abord le champ 'Hex preview' fourni ci-dessous.",
            "Réponds en français.",
        )
    };
    let _ = lang_instr; // used via scope_restriction

    let mut prompt = scope_restriction.to_string();

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
            "\n\nActive packet context:\nTimestamp: {}\nSource: {}:{} ({})\nDestination: {}:{} ({})\nL3/Proto: {}/{}\nEtherType: {}\nTTL/Hop: {}\nTCP Flags: {}\nLength: {} bytes\nInfo: {}\nHex preview: {}",
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
        prompt.push_str("\n\nRAG context:\n");
        prompt.push_str(&context.prompt_block);
    }

    prompt.push_str("\n\nUser question:\n");
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
        "Type: {} / {}\nRoute: {}:{} ({}) -> {}:{} ({})\nSize: {} bytes\nTTL/Hop: {}\nTCP Flags: {}\nEtherType: {}\nSummary: {}\nHex preview: {}",
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
