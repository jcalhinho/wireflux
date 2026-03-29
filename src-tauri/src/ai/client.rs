use reqwest::Client;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    prompt: String,
    stream: bool,
    think: bool,
    options: OllamaGenerateOptions,
}

#[derive(Debug, Serialize)]
struct OllamaChatRequest<'a> {
    model: &'a str,
    messages: Vec<OllamaChatMessage>,
    stream: bool,
    think: bool,
    options: OllamaGenerateOptions,
}

#[derive(Debug, Serialize)]
struct OllamaChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OllamaGenerateOptions {
    num_predict: u32,
    temperature: f32,
    top_p: f32,
}

pub async fn generate_ollama(
    client: &Client,
    endpoint: &str,
    model: &str,
    prompt: String,
    num_predict: u32,
) -> Result<String, String> {
    let body = OllamaRequest {
        model,
        prompt,
        stream: false,
        think: false,
        options: OllamaGenerateOptions {
            num_predict,
            temperature: 0.2,
            top_p: 0.9,
        },
    };

    let resp = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|error| format!("Connexion Ollama impossible: {error}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "corps d'erreur indisponible".to_string());
        return Err(format!(
            "Ollama HTTP {}: {}",
            status.as_u16(),
            body_text.trim()
        ));
    }

    let parsed = resp
        .json::<Value>()
        .await
        .map_err(|error| format!("Réponse Ollama illisible: {error}"))?;

    if let Some(text) = extract_text_from_ollama_payload(&parsed) {
        return Ok(text);
    }

    let done_reason = parsed
        .get("done_reason")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let preview = compact_json_preview(&parsed, 280);
    Err(format!(
        "Réponse Ollama vide (done_reason={done_reason}, payload={preview})"
    ))
}

pub async fn generate_ollama_stream<F>(
    client: &Client,
    endpoint: &str,
    model: &str,
    prompt: String,
    num_predict: u32,
    mut on_chunk: F,
) -> Result<String, String>
where
    F: FnMut(String),
{
    let body = OllamaRequest {
        model,
        prompt,
        stream: true,
        think: false,
        options: OllamaGenerateOptions {
            num_predict,
            temperature: 0.2,
            top_p: 0.9,
        },
    };

    let mut resp = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|error| format!("Connexion Ollama impossible: {error}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "corps d'erreur indisponible".to_string());
        return Err(format!(
            "Ollama HTTP {}: {}",
            status.as_u16(),
            body_text.trim()
        ));
    }

    let mut pending = String::new();
    let mut full = String::new();

    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|error| format!("Lecture stream Ollama impossible: {error}"))?
    {
        pending.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(index) = pending.find('\n') {
            let line = pending[..index].to_string();
            pending = pending[index + 1..].to_string();
            process_stream_line(&line, &mut full, &mut on_chunk)?;
        }
    }

    let tail = pending;
    if !tail.trim().is_empty() {
        process_stream_line(&tail, &mut full, &mut on_chunk)?;
    }

    if full.trim().is_empty() {
        return Err("Réponse Ollama stream vide".to_string());
    }

    Ok(full)
}

pub async fn generate_ollama_chat(
    client: &Client,
    endpoint: &str,
    model: &str,
    prompt: String,
    num_predict: u32,
) -> Result<String, String> {
    let body = OllamaChatRequest {
        model,
        messages: vec![
            OllamaChatMessage {
                role: "system".to_string(),
                content: "Tu dois répondre uniquement avec le résultat final. N'affiche jamais de thinking process ni raisonnement interne.".to_string(),
            },
            OllamaChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ],
        stream: false,
        think: false,
        options: OllamaGenerateOptions {
            num_predict,
            temperature: 0.2,
            top_p: 0.9,
        },
    };

    let resp = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|error| format!("Connexion Ollama (/api/chat) impossible: {error}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "corps d'erreur indisponible".to_string());
        return Err(format!(
            "Ollama /api/chat HTTP {}: {}",
            status.as_u16(),
            body_text.trim()
        ));
    }

    let parsed = resp
        .json::<Value>()
        .await
        .map_err(|error| format!("Réponse Ollama /api/chat illisible: {error}"))?;

    if let Some(text) = extract_text_from_ollama_payload(&parsed) {
        return Ok(text);
    }

    let done_reason = parsed
        .get("done_reason")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let preview = compact_json_preview(&parsed, 280);
    Err(format!(
        "Réponse Ollama /api/chat vide (done_reason={done_reason}, payload={preview})"
    ))
}

pub fn is_length_error(error: &str) -> bool {
    error.contains("done_reason=length") || error.to_ascii_lowercase().contains("length")
}

fn process_stream_line<F>(line: &str, full: &mut String, on_chunk: &mut F) -> Result<(), String>
where
    F: FnMut(String),
{
    if line.trim().is_empty() {
        return Ok(());
    }

    let parsed: Value = serde_json::from_str(line)
        .map_err(|error| format!("Ligne stream Ollama invalide: {error}"))?;

    if let Some(error) = parsed.get("error").and_then(Value::as_str) {
        return Err(format!("Ollama stream error: {error}"));
    }

    if let Some(piece) = parsed.get("response").and_then(Value::as_str) {
        let sanitized = sanitize_model_chunk(piece);
        if !sanitized.is_empty() {
            full.push_str(&sanitized);
            on_chunk(sanitized);
        }
    }

    Ok(())
}

fn extract_text_from_ollama_payload(payload: &Value) -> Option<String> {
    let candidates = [
        payload.get("response").and_then(Value::as_str),
        payload.get("content").and_then(Value::as_str),
        payload
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str),
    ];

    for candidate in candidates.into_iter().flatten() {
        let sanitized = sanitize_model_answer(candidate);
        if !sanitized.is_empty() {
            return Some(sanitized);
        }
    }

    None
}

fn sanitize_model_chunk(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let trimmed = text.trim();
    if trimmed.is_empty() {
        // Important: spaces can be emitted as standalone chunks in stream mode.
        return text.to_string();
    }

    if looks_like_internal_reasoning(trimmed) {
        return String::new();
    }

    text.to_string()
}

fn sanitize_model_answer(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if looks_like_internal_reasoning(trimmed) {
        return String::new();
    }

    trimmed.to_string()
}

fn looks_like_internal_reasoning(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let markers = [
        "thinking process",
        "analyze the request",
        "target audience",
        "task:",
        "input data:",
        "reasoning",
        "chain of thought",
    ];
    markers.iter().any(|marker| lower.contains(marker))
}

fn compact_json_preview(payload: &Value, max_len: usize) -> String {
    let raw = payload.to_string().replace('\n', " ");
    if raw.len() <= max_len {
        return raw;
    }
    format!("{}...", &raw[..max_len])
}
