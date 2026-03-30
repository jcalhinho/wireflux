mod client;
mod profiles;
mod prompt;
mod rag;
mod service;

use crate::packet::PacketRecord;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

pub use profiles::AiHealthStatus;
use profiles::{preferred_model_from_env, resolve_model, ModelResolution};
use rag::build_rag_context;
use prompt::{build_chat_prompt, build_compact_prompt, build_prompt, local_explanation};
use service::{ensure_ollama_online, fetch_installed_models};

#[derive(Debug, Clone, Serialize)]
struct AiStreamChunkEvent {
    request_id: String,
    chunk: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiStreamDoneEvent {
    request_id: String,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct AiStreamErrorEvent {
    request_id: String,
    message: String,
}

pub async fn explain_packet(
    packet: PacketRecord,
    requested_model: Option<String>,
) -> Result<String, String> {
    let base_url = std::env::var("WIREFLUX_OLLAMA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
    let base_url = base_url.trim_end_matches('/').to_string();

    let inference_timeout_secs = std::env::var("WIREFLUX_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(90);

    let client = Client::builder()
        .timeout(Duration::from_secs(inference_timeout_secs))
        .build()
        .map_err(|error| format!("Impossible d'initialiser le client HTTP IA: {error}"))?;

    let ollama_note = ensure_ollama_online(&client, &base_url).await?;
    let models = fetch_installed_models(&client, &base_url).await?;
    if models.is_empty() {
        return Err(
            "Aucun modèle Ollama installé. Installe un modèle via `ollama pull <model>`."
                .to_string(),
        );
    }

    let preferred = preferred_model_from_env();
    let resolution = resolve_model(requested_model.as_deref(), preferred.as_deref(), &models);
    let (selected_model, model_note) = match resolution {
        ModelResolution::Selected { model, note } => (model, note),
        ModelResolution::NeedSelection { models } => {
            return Err(format!(
                "Plusieurs modèles disponibles: {}. Sélectionne un modèle dans l'interface.",
                models.join(", ")
            ))
        }
    };

    let endpoint = format!("{base_url}/api/generate");
    let chat_endpoint = format!("{base_url}/api/chat");
    let num_predict = std::env::var("WIREFLUX_OLLAMA_NUM_PREDICT")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(384);

    let rag_context = build_rag_context(&packet);
    let primary_prompt = build_prompt(&packet, rag_context.as_ref(), "fr");
    let compact_prompt = build_compact_prompt(&packet, rag_context.as_ref(), "fr");
    let retry_predict = num_predict.max(256);
    let length_retry_predict = num_predict.saturating_mul(3).clamp(384, 1200);
    let mut notes: Vec<String> = Vec::new();

    let answer_text = match client::generate_ollama(
        &client,
        &endpoint,
        &selected_model,
        primary_prompt.clone(),
        num_predict,
    )
    .await
    {
        Ok(text) => text,
        Err(primary_error) => {
            notes.push(format!("tentative principale échouée: {primary_error}"));

            if client::is_length_error(&primary_error) {
                match client::generate_ollama(
                    &client,
                    &endpoint,
                    &selected_model,
                    primary_prompt.clone(),
                    length_retry_predict,
                )
                .await
                {
                    Ok(text) => {
                        notes.push(format!(
                            "retry large budget réussi (num_predict={length_retry_predict})"
                        ));
                        return finalize_answer(
                            text,
                            &selected_model,
                            model_note,
                            ollama_note,
                            rag_context.as_ref(),
                            notes,
                        );
                    }
                    Err(length_retry_error) => {
                        notes.push(format!("retry large budget échoué: {length_retry_error}"));
                    }
                }
            }

            match client::generate_ollama(
                &client,
                &endpoint,
                &selected_model,
                compact_prompt.clone(),
                retry_predict,
            )
            .await
            {
                Ok(text) => {
                    notes.push("retry generate compact prompt réussi".to_string());
                    text
                }
                Err(second_error) => {
                    notes.push(format!("retry generate compact échoué: {second_error}"));
                    match client::generate_ollama_chat(
                        &client,
                        &chat_endpoint,
                        &selected_model,
                        compact_prompt.clone(),
                        retry_predict,
                    )
                    .await
                    {
                        Ok(text) => {
                            notes.push("fallback chat endpoint réussi".to_string());
                            text
                        }
                        Err(chat_error) => {
                            notes.push(format!("fallback chat échoué: {chat_error}"));
                            let fallback = local_explanation(&packet);
                            let rag_note = rag_context
                                .as_ref()
                                .map(|context| {
                                    format!(
                                        "\n[RAG: {} preuve(s) locale(s), corpus={}]",
                                        context.evidence_count, context.corpus_label
                                    )
                                })
                                .unwrap_or_default();
                            return Ok(format!(
                                "{}{}\n\n[Source IA: fallback local]\n[Diagnostic: {}]",
                                fallback,
                                rag_note,
                                notes.join(" | ")
                            ));
                        }
                    }
                }
            }
        }
    };

    finalize_answer(
        answer_text,
        &selected_model,
        model_note,
        ollama_note,
        rag_context.as_ref(),
        notes,
    )
}

pub async fn ask_ai_question(
    question: String,
    requested_model: Option<String>,
    packet: Option<PacketRecord>,
    lang: Option<String>,
) -> Result<String, String> {
    let trimmed_question = question.trim();
    if trimmed_question.is_empty() {
        return Err("Question vide: écris une question avant envoi.".to_string());
    }

    let base_url = std::env::var("WIREFLUX_OLLAMA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
    let base_url = base_url.trim_end_matches('/').to_string();

    let inference_timeout_secs = std::env::var("WIREFLUX_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(90);

    let client = Client::builder()
        .timeout(Duration::from_secs(inference_timeout_secs))
        .build()
        .map_err(|error| format!("Impossible d'initialiser le client HTTP IA: {error}"))?;

    let ollama_note = ensure_ollama_online(&client, &base_url).await?;
    let models = fetch_installed_models(&client, &base_url).await?;
    if models.is_empty() {
        return Err(
            "Aucun modèle Ollama installé. Installe un modèle via `ollama pull <model>`."
                .to_string(),
        );
    }

    let preferred = preferred_model_from_env();
    let resolution = resolve_model(requested_model.as_deref(), preferred.as_deref(), &models);
    let (selected_model, model_note) = match resolution {
        ModelResolution::Selected { model, note } => (model, note),
        ModelResolution::NeedSelection { models } => {
            return Err(format!(
                "Plusieurs modèles disponibles: {}. Sélectionne un modèle dans l'interface.",
                models.join(", ")
            ))
        }
    };

    let endpoint = format!("{base_url}/api/chat");
    let num_predict = std::env::var("WIREFLUX_OLLAMA_NUM_PREDICT")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(520)
        .max(384);

    let rag_context = packet.as_ref().and_then(build_rag_context);
    let lang_str = lang.as_deref().unwrap_or("fr");
    let prompt = build_chat_prompt(trimmed_question, packet.as_ref(), rag_context.as_ref(), lang_str);

    match client::generate_ollama_chat(&client, &endpoint, &selected_model, prompt, num_predict).await
    {
        Ok(answer_text) => finalize_answer(
            answer_text,
            &selected_model,
            model_note,
            ollama_note,
            rag_context.as_ref(),
            Vec::new(),
        ),
        Err(error) => {
            let fallback = if let Some(packet) = packet.as_ref() {
                format!(
                    "{}\n\nQuestion: {}\nRéponse locale: Ollama indisponible pour cette question.",
                    local_explanation(packet),
                    trimmed_question
                )
            } else {
                format!(
                    "Impossible de répondre via Ollama pour la question: \"{}\".",
                    trimmed_question
                )
            };
            Ok(format!(
                "{}\n\n[Source IA: fallback local]\n[Diagnostic: {}]",
                fallback, error
            ))
        }
    }
}

pub async fn explain_packet_stream(
    app: AppHandle,
    packet: PacketRecord,
    requested_model: Option<String>,
    request_id: String,
    lang: Option<String>,
) -> Result<(), String> {
    let base_url = std::env::var("WIREFLUX_OLLAMA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
    let base_url = base_url.trim_end_matches('/').to_string();

    let inference_timeout_secs = std::env::var("WIREFLUX_OLLAMA_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(90);

    let client = Client::builder()
        .timeout(Duration::from_secs(inference_timeout_secs))
        .build()
        .map_err(|error| format!("Impossible d'initialiser le client HTTP IA: {error}"))?;

    let ollama_note = ensure_ollama_online(&client, &base_url).await?;
    let models = fetch_installed_models(&client, &base_url).await?;
    if models.is_empty() {
        emit_stream_error(
            &app,
            &request_id,
            "Aucun modèle Ollama installé. Installe un modèle via `ollama pull <model>`.",
        );
        return Ok(());
    }

    let preferred = preferred_model_from_env();
    let resolution = resolve_model(requested_model.as_deref(), preferred.as_deref(), &models);
    let (selected_model, model_note) = match resolution {
        ModelResolution::Selected { model, note } => (model, note),
        ModelResolution::NeedSelection { models } => {
            emit_stream_error(
                &app,
                &request_id,
                &format!(
                    "Plusieurs modèles disponibles: {}. Sélectionne un modèle dans l'interface.",
                    models.join(", ")
                ),
            );
            return Ok(());
        }
    };

    let endpoint = format!("{base_url}/api/generate");
    let num_predict = std::env::var("WIREFLUX_OLLAMA_NUM_PREDICT")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(520)
        .max(384);

    let rag_context = build_rag_context(&packet);
    let lang_str = lang.as_deref().unwrap_or("fr");
    let primary_prompt = build_prompt(&packet, rag_context.as_ref(), lang_str);
    let app_for_chunks = app.clone();
    let request_for_chunks = request_id.clone();

    match client::generate_ollama_stream(
        &client,
        &endpoint,
        &selected_model,
        primary_prompt,
        num_predict,
        move |chunk| {
            let _ = app_for_chunks.emit(
                "ai-stream-chunk",
                AiStreamChunkEvent {
                    request_id: request_for_chunks.clone(),
                    chunk,
                },
            );
        },
    )
    .await
    {
        Ok(text) => {
            let final_text = finalize_answer(
                text,
                &selected_model,
                model_note,
                ollama_note,
                rag_context.as_ref(),
                Vec::new(),
            )?;
            let _ = app.emit(
                "ai-stream-done",
                AiStreamDoneEvent {
                    request_id,
                    text: final_text,
                },
            );
            Ok(())
        }
        Err(stream_error) => {
            let fallback_packet = packet.clone();
            let fallback_model = selected_model.clone();
            let fallback_text = explain_packet(packet, Some(fallback_model))
                .await
                .unwrap_or_else(|_| {
                    format!(
                        "{}\n\n[Source IA: fallback local]\n[Diagnostic: stream indisponible: {}]",
                        local_explanation(&fallback_packet),
                        stream_error
                    )
                });
            let _ = app.emit(
                "ai-stream-done",
                AiStreamDoneEvent {
                    request_id,
                    text: fallback_text,
                },
            );
            Ok(())
        }
    }
}

pub async fn ai_status() -> AiHealthStatus {
    let base_url = std::env::var("WIREFLUX_OLLAMA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
    let base_url = base_url.trim_end_matches('/').to_string();

    let client = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(error) => {
            return AiHealthStatus {
                state: "error".to_string(),
                message: format!("client HTTP IA invalide: {error}"),
                models: Vec::new(),
                selected_model: None,
                requires_selection: false,
            };
        }
    };

    let service_note = match ensure_ollama_online(&client, &base_url).await {
        Ok(note) => note,
        Err(error) => {
            return AiHealthStatus {
                state: "offline".to_string(),
                message: error,
                models: Vec::new(),
                selected_model: None,
                requires_selection: false,
            };
        }
    };

    let models = match fetch_installed_models(&client, &base_url).await {
        Ok(models) => models,
        Err(error) => {
            return AiHealthStatus {
                state: "error".to_string(),
                message: error,
                models: Vec::new(),
                selected_model: None,
                requires_selection: false,
            };
        }
    };

    if models.is_empty() {
        return AiHealthStatus {
            state: "offline".to_string(),
            message: "Ollama actif mais aucun modèle installé.".to_string(),
            models,
            selected_model: None,
            requires_selection: false,
        };
    }

    let preferred = preferred_model_from_env();
    let resolution = resolve_model(None, preferred.as_deref(), &models);
    match resolution {
        ModelResolution::Selected { model, note } => {
            let mut parts = vec![format!("connectée (modèle: {model})")];
            if let Some(service_note) = service_note {
                parts.push(service_note);
            }
            if let Some(note) = note {
                parts.push(note);
            }
            AiHealthStatus {
                state: "ready".to_string(),
                message: parts.join(" | "),
                models,
                selected_model: Some(model),
                requires_selection: false,
            }
        }
        ModelResolution::NeedSelection { .. } => AiHealthStatus {
            state: "needs_selection".to_string(),
            message: "Plusieurs modèles détectés: sélection requise.".to_string(),
            models,
            selected_model: None,
            requires_selection: true,
        },
    }
}

fn finalize_answer(
    answer_text: String,
    selected_model: &str,
    model_note: Option<String>,
    ollama_note: Option<String>,
    rag_context: Option<&rag::RagContext>,
    notes: Vec<String>,
) -> Result<String, String> {
    let mut text = format!(
        "{}\n\n[Source IA: Ollama model={}]",
        answer_text.trim(),
        selected_model
    );
    if let Some(context) = rag_context {
        text.push_str(&format!(
            "\n[Info RAG: {} preuve(s) locale(s), corpus={}]",
            context.evidence_count, context.corpus_label
        ));
    }
    if let Some(note) = model_note {
        text.push_str(&format!("\n[Info modèle: {}]", note));
    }
    if let Some(note) = ollama_note {
        text.push_str(&format!("\n[Info service: {}]", note));
    }
    if !notes.is_empty() {
        text.push_str(&format!("\n[Info robustesse: {}]", notes.join(" | ")));
    }
    Ok(text)
}

fn emit_stream_error(app: &AppHandle, request_id: &str, message: &str) {
    let _ = app.emit(
        "ai-stream-error",
        AiStreamErrorEvent {
            request_id: request_id.to_string(),
            message: message.to_string(),
        },
    );
}
