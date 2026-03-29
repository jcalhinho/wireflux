use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AiHealthStatus {
    pub state: String,
    pub message: String,
    pub models: Vec<String>,
    pub selected_model: Option<String>,
    pub requires_selection: bool,
}

#[derive(Debug)]
pub enum ModelResolution {
    Selected { model: String, note: Option<String> },
    NeedSelection { models: Vec<String> },
}

pub fn preferred_model_from_env() -> Option<String> {
    std::env::var("WIREFLUX_OLLAMA_MODEL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn resolve_model(
    requested_model: Option<&str>,
    preferred_model: Option<&str>,
    models: &[String],
) -> ModelResolution {
    if let Some(requested) = requested_model {
        if models.iter().any(|model| model == requested) {
            return ModelResolution::Selected {
                model: requested.to_string(),
                note: None,
            };
        }
    }

    if let Some(preferred) = preferred_model {
        if models.iter().any(|model| model == preferred) {
            return ModelResolution::Selected {
                model: preferred.to_string(),
                note: None,
            };
        }
    }

    if models.len() == 1 {
        let only_model = models[0].clone();
        let note = if let Some(preferred) = preferred_model {
            Some(format!(
                "modèle préféré `{preferred}` introuvable, bascule auto vers `{only_model}`"
            ))
        } else {
            Some("un seul modèle disponible, sélection automatique".to_string())
        };
        return ModelResolution::Selected {
            model: only_model,
            note,
        };
    }

    ModelResolution::NeedSelection {
        models: models.to_vec(),
    }
}
