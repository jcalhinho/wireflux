use reqwest::Client;
use serde::Deserialize;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

static OLLAMA_BOOT_ATTEMPTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelTag>,
}

#[derive(Debug, Deserialize)]
struct OllamaModelTag {
    name: String,
}

pub async fn ensure_ollama_online(
    client: &Client,
    base_url: &str,
) -> Result<Option<String>, String> {
    if is_ollama_reachable(client, base_url).await {
        return Ok(None);
    }

    if !is_local_ollama_url(base_url) {
        return Err(format!("Ollama distant indisponible: {base_url}"));
    }

    let note = ensure_local_ollama_started()?;
    if !wait_for_ollama(client, base_url, 16, Duration::from_millis(250)).await {
        return Err(format!(
            "Ollama local indisponible sur {base_url} après tentative de démarrage automatique."
        ));
    }
    Ok(Some(note))
}

pub async fn fetch_installed_models(client: &Client, base_url: &str) -> Result<Vec<String>, String> {
    let tags_url = format!("{base_url}/api/tags");
    let response = client
        .get(tags_url)
        .send()
        .await
        .map_err(|error| format!("Impossible de lire les modèles Ollama: {error}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "Impossible de lire les modèles Ollama (HTTP {})",
            response.status().as_u16()
        ));
    }

    let tags = response
        .json::<OllamaTagsResponse>()
        .await
        .map_err(|error| format!("Réponse `/api/tags` invalide: {error}"))?;

    Ok(tags.models.into_iter().map(|model| model.name).collect())
}

fn is_local_ollama_url(base_url: &str) -> bool {
    base_url.contains("127.0.0.1") || base_url.contains("localhost")
}

fn ensure_local_ollama_started() -> Result<String, String> {
    if OLLAMA_BOOT_ATTEMPTED.swap(true, Ordering::SeqCst) {
        return Ok("démarrage auto déjà tenté dans cette session".to_string());
    }

    Command::new("ollama")
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("impossible de lancer `ollama serve`: {error}"))?;

    Ok("`ollama serve` lancé automatiquement".to_string())
}

async fn is_ollama_reachable(client: &Client, base_url: &str) -> bool {
    let tags_url = format!("{base_url}/api/tags");
    match client.get(tags_url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

async fn wait_for_ollama(
    client: &Client,
    base_url: &str,
    attempts: usize,
    sleep_interval: Duration,
) -> bool {
    for _ in 0..attempts {
        if is_ollama_reachable(client, base_url).await {
            return true;
        }
        thread::sleep(sleep_interval);
    }
    false
}
