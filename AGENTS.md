# Wireflux - AGENTS.md

## Purpose
Analyseur réseau éducatif, simple et robuste, avec explication AI optionnelle.
Le projet privilégie la stabilité de la capture et la lisibilité UX.

---

## Stack (current baseline)
- Tauri v2
- Frontend: Vanilla JS + Vite
- Core: Rust
- Capture live: `dumpcap` piloté par Rust
- Parsing: parser PCAP côté Rust
- AI optionnelle: Ollama HTTP (`/api/generate`)

---

## Repository Architecture
- `index.html` + `src/`: UI minimale (table paquets, start/stop, explication)
- `src-tauri/src/main.rs`: commandes Tauri + wiring global
- `src-tauri/src/capture.rs`: gestion capture, start/stop, émission événements
- `src-tauri/src/packet.rs`: modèle paquet + parsing L2/L3
- `src-tauri/src/ai.rs`: explication AI optionnelle avec fallback local

---

## Technical Rules
1. Capture d’abord:
- la fiabilité `start/stop/restart` est prioritaire sur les features visuelles.

2. Source de vérité live:
- pas de `pyshark`, pas de backend Python.
- capture via `dumpcap` uniquement.

3. Parsing:
- parsing en Rust, déterministe.
- éviter les heuristiques opaques.

4. AI:
- optionnelle et non bloquante.
- si Ollama indisponible: fallback local explicite.
- aucun modèle embarqué.

5. UI:
- pas de framework frontend lourd tant que le MVP n’est pas stabilisé.
- pas de blocage UI pendant capture ou stop.

---

## Performance & Reliability
- gérer 10k+ paquets sans freeze UI.
- limiter la taille du rendu table (fenêtre affichée) sans perdre l’état utile.
- éviter tout état zombie (`stopping` bloqué, thread non nettoyé).

---

## Security & Safety Baseline
- ne jamais logger secrets/tokens.
- valider toutes les entrées externes (interface, réponses AI, commandes système).
- erreurs explicites, jamais silencieuses.

---

## Workflow
1. Petite diff, testable, réversible.
2. Vérifier compilation frontend + rust après chaque changement.
3. Ne pas réintroduire des artefacts legacy Python.

---

## Forbidden
- Retour à PyQt/pyshark/scapy dans ce repo.
- Fonctionnalités “nice-to-have” qui cassent la stabilité capture.
- Bundling de modèles AI.

---

## Done when
- start/stop/restart capture fiables
- flux paquets visible en temps réel
- sélection paquet + explication (AI ou fallback)
- build frontend OK
- `cargo check` OK
