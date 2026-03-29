# Wireflux — Packet Laboratory

> **English** · [Français](#français)

---

## English

### What is Wireflux?

Wireflux is an educational desktop application for live network packet capture and analysis. It is designed for students, educators, and anyone learning network security or protocols from the ground up.

Rather than overwhelming the user with raw hex dumps and cryptic columns, Wireflux explains **what each packet is doing**, layer by layer, using optional local AI (via Ollama) with a graceful fallback to deterministic local explanations when no AI is available.

**This is not Wireshark.** Wireflux is intentionally simpler, more opinionated, and pedagogically oriented. Capture reliability and clarity always come before feature density.

---

### Features

#### Live Capture & Parsing
- Real-time packet capture via `dumpcap` (Wireshark's capture binary)
- Deterministic Rust parser: Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP/ICMPv6
- TCP flag extraction (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
- TTL/Hop Limit, EtherType, hex payload preview
- Packets stored in memory (up to 10,000 per session)

#### AI Explanations (Optional)
- Local Ollama integration (`/api/generate` + `/api/chat`)
- Automatic model detection — picks the only model if one is installed, prompts for selection if multiple
- Multi-stage retry pipeline: full prompt → compact prompt → local fallback
- Auto-starts `ollama serve` if localhost endpoint is unreachable
- Never blocks the UI: graceful fallback to deterministic local explanation

#### Educational Interface
- **OSI Layer Navigation**: 7 tabs (L1 Physical → L7 Application) to filter packet view by layer
- **Guided Explanation Panel**: structured summary of each packet with protocol context
- **Protocol Coach**: contextual multiple-choice quiz generated from the selected packet
- **Handshake Decoder**: step-by-step TCP (and TLS) handshake visualizer per conversation
- **Story Session**: chronological timeline of key network events (DNS, SYN, TLS, data)
- **Flow Map**: 5-tuple conversation list with normality score (0–100)

#### Behavioral Detection
Five heuristic rules run continuously during capture:

| Rule | Threshold | Window |
|------|-----------|--------|
| SYN Scan | 12+ unique targets | 15 s |
| Brute Force | 8+ attempts on sensitive ports | 20 s |
| Beaconing (C2) | 6+ packets, periodic interval | 120 s |
| Data Exfiltration | 600 KB or 24+ packets outbound | 10 s |
| Traffic Spike | 3.5× above rolling baseline | ~12 s |

Rules can be toggled individually. Alerts appear in real time with severity levels (low / medium / high).

#### Export
- **CSV** — packet table (ID, timestamp, source, destination, protocol, size, flags, info)
- **JSON** — raw packet records
- Live traffic **ECharts graph** (packets/sec + bytes/sec), expandable to full-screen modal

---

### Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| [Rust](https://rustup.rs) | 1.70+ | `rustup` recommended |
| [Node.js](https://nodejs.org) | 20+ | LTS recommended |
| [dumpcap](https://www.wireshark.org) | any | Bundled with Wireshark |
| [Ollama](https://ollama.com) | any | **Optional** — AI explanations only |

**macOS**: Install [Wireshark](https://www.wireshark.org/download.html) and run the `ChmodBPF` package it ships with to allow unprivileged capture.

**Linux**: `dumpcap` requires either `sudo` or the `cap_net_raw` / `cap_net_admin` capabilities set on the binary.

**Windows**: Run the application as Administrator, or configure Npcap permissions.

---

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/wireflux.git
cd wireflux

# 2. Install Node dependencies
npm install

# 3. Start in development mode
npm run tauri dev

# 4. Build a release binary
npm run tauri build
```

Release binaries are written to `src-tauri/target/release/`:
- macOS: `.dmg` / `.app`
- Linux: `.AppImage` / `.deb`
- Windows: `.msi` / `.exe`

---

### AI Setup (optional)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (any instruction-tuned model works)
ollama pull mistral
# or: ollama pull llama3, neural-chat, phi3, etc.
```

Wireflux auto-detects Ollama on `http://127.0.0.1:11434`. If the process is not running, it will attempt to start it automatically.

---

### Configuration

All settings are optional. Set these environment variables before launching:

```bash
# Ollama endpoint (default: http://127.0.0.1:11434)
export WIREFLUX_OLLAMA_URL=http://127.0.0.1:11434

# Force a specific model (default: auto-detect)
export WIREFLUX_OLLAMA_MODEL=mistral

# Request timeout in seconds (default: 90)
export WIREFLUX_OLLAMA_TIMEOUT_SECS=90

# Max tokens generated per explanation (default: 384)
export WIREFLUX_OLLAMA_NUM_PREDICT=384
```

---

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Space` | Start / Stop capture |
| `←` / `→` | Previous / Next page |
| `↑` / `↓` | Navigate packets in current page |
| `Escape` | Close graph modal |

---

### Architecture

```
wireflux/
├── index.html                  — App shell HTML
├── src/
│   ├── main.js                 — Entry point, event wiring
│   ├── app/
│   │   ├── domState.js         — Global state, DOM refs, constants
│   │   ├── capture.js          — Tauri command calls, interface loading
│   │   ├── alerts.js           — Behavioral detection rules
│   │   ├── explainCoach.js     — AI explanation + protocol quiz
│   │   ├── storyFlow.js        — Conversation tracking, story timeline
│   │   ├── tableView.js        — Packet table rendering, filtering, pagination
│   │   ├── charts.js           — ECharts live traffic graph
│   │   ├── handshakeView.js    — TCP/TLS handshake decoder
│   │   ├── uiControls.js       — Panel toggles, OSI layer tabs
│   │   └── helpers.js          — Protocol parsing utilities
│   └── styles/
│       ├── base.css            — Layout, topbar, sidenav
│       ├── panels.css          — Panel cards, modal
│       ├── topology-learning.css
│       └── insights-responsive.css
└── src-tauri/
    └── src/
        ├── main.rs             — Tauri builder, command registration
        ├── capture.rs          — CaptureManager, dumpcap control, PCAP live-tail
        ├── packet.rs           — PacketRecord, L2/L3/L4 byte parser
        ├── exports.rs          — CSV / JSON export
        └── ai/
            ├── mod.rs          — AI orchestration, retry pipeline
            ├── client.rs       — Ollama HTTP client
            ├── service.rs      — Health check, auto-boot, model list
            ├── profiles.rs     — Model resolution logic
            └── prompt.rs       — Prompt templates, local fallback
```

**Data flow**:
```
User clicks Start
  → Rust spawns dumpcap → writes /tmp/*.pcap
  → Rust tail-reads PCAP file → parses packets
  → Emits `packet-batch` event → JS updates state
  → User clicks packet → JS calls explain_packet()
  → Rust queries Ollama (or returns local fallback)
  → JS renders explanation + quiz + handshake decoder
```

---

### Troubleshooting

| Problem | Solution |
|---------|----------|
| `dumpcap: permission denied` | macOS: run ChmodBPF. Linux: `sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)`. Windows: run as Admin |
| No interfaces listed | Ensure Wireshark / dumpcap is installed and on your PATH |
| AI timeout | Increase `WIREFLUX_OLLAMA_TIMEOUT_SECS`. Smaller models are faster |
| No models available | Run `ollama pull mistral` (or any model) |
| Ollama not starting | Run `ollama serve` manually and check the port |
| App crashes on stop | Known issue with some dumpcap versions — restart the app |

---

### Contributing

Contributions are welcome. Before opening a pull request:

1. Run `cargo clippy -- -D warnings` and `cargo fmt`
2. Verify the app builds with `npm run tauri build`
3. Keep the JS side dependency-free (no new npm runtime packages)
4. Follow the project philosophy in `AGENTS.md`: **capture stability over features**

---

### License

> License to be determined before first public release.

---

---

## Français

### C'est quoi Wireflux ?

Wireflux est une application de bureau éducative pour la capture et l'analyse de paquets réseau en temps réel. Elle s'adresse aux étudiants, aux enseignants et à toute personne qui apprend les protocoles réseau ou la sécurité informatique.

Plutôt que de noyer l'utilisateur dans des dumps hexadécimaux et des colonnes cryptiques, Wireflux **explique ce que chaque paquet fait**, couche par couche, en utilisant une IA locale optionnelle (via Ollama) avec un repli gracieux vers des explications déterministes si aucune IA n'est disponible.

**Ce n'est pas Wireshark.** Wireflux est volontairement plus simple, plus opinioné et orienté pédagogie. La fiabilité de la capture et la clarté passent toujours avant la densité de fonctionnalités.

---

### Fonctionnalités

#### Capture live & parsing
- Capture de paquets en temps réel via `dumpcap` (le binaire de capture de Wireshark)
- Parser Rust déterministe : Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP/ICMPv6
- Extraction des flags TCP (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
- TTL/Hop Limit, EtherType, aperçu hexadécimal du payload
- Jusqu'à 10 000 paquets stockés en mémoire par session

#### Explications IA (optionnelles)
- Intégration Ollama locale (`/api/generate` + `/api/chat`)
- Détection automatique du modèle — sélection automatique si un seul modèle est installé, choix explicite si plusieurs
- Pipeline de retry multi-étapes : prompt complet → prompt compact → fallback local
- Démarre `ollama serve` automatiquement si le port local est injoignable
- Jamais bloquant : repli gracieux vers une explication locale déterministe

#### Interface éducative
- **Navigation couches OSI** : 7 onglets (L1 Physique → L7 Application) pour filtrer la vue par couche
- **Panneau d'explication guidée** : résumé structuré de chaque paquet avec contexte protocolaire
- **Protocol Coach** : quiz contextuel à choix multiples généré depuis le paquet sélectionné
- **Décodeur Handshake** : visualiseur pas à pas du handshake TCP (et TLS) par conversation
- **Mode Story Session** : chronologie des événements réseau clés (DNS, SYN, TLS, données)
- **Flow Map** : liste des conversations 5-tuple avec score de normalité (0–100)

#### Détection comportementale
Cinq règles heuristiques tournent en continu pendant la capture :

| Règle | Seuil | Fenêtre |
|-------|-------|---------|
| Scan SYN | 12+ cibles uniques | 15 s |
| Brute Force | 8+ tentatives sur ports sensibles | 20 s |
| Beaconing (C2) | 6+ paquets, intervalle périodique | 120 s |
| Exfiltration de données | 600 Ko ou 24+ paquets sortants | 10 s |
| Pic de trafic | 3,5× au-dessus de la baseline glissante | ~12 s |

Les règles sont activables/désactivables individuellement. Les alertes apparaissent en temps réel avec un niveau de sévérité (faible / moyen / élevé).

#### Export
- **CSV** — table des paquets (ID, timestamp, source, destination, protocole, taille, flags, info)
- **JSON** — enregistrements bruts des paquets
- **Graphe ECharts live** (paquets/sec + octets/sec), extensible en modal plein écran

---

### Prérequis

| Dépendance | Version | Notes |
|------------|---------|-------|
| [Rust](https://rustup.rs) | 1.70+ | `rustup` recommandé |
| [Node.js](https://nodejs.org) | 20+ | LTS recommandé |
| [dumpcap](https://www.wireshark.org) | toute | Fourni avec Wireshark |
| [Ollama](https://ollama.com) | toute | **Optionnel** — explications IA uniquement |

**macOS** : Installez [Wireshark](https://www.wireshark.org/download.html) et exécutez le paquet `ChmodBPF` fourni pour autoriser la capture sans privilèges root.

**Linux** : `dumpcap` nécessite soit `sudo`, soit les capabilities `cap_net_raw` / `cap_net_admin` définies sur le binaire.

**Windows** : Lancez l'application en tant qu'Administrateur, ou configurez les permissions Npcap.

---

### Installation

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-org/wireflux.git
cd wireflux

# 2. Installer les dépendances Node
npm install

# 3. Démarrer en mode développement
npm run tauri dev

# 4. Compiler un binaire de release
npm run tauri build
```

Les binaires de release sont écrits dans `src-tauri/target/release/` :
- macOS : `.dmg` / `.app`
- Linux : `.AppImage` / `.deb`
- Windows : `.msi` / `.exe`

---

### Configuration IA (optionnelle)

```bash
# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Télécharger un modèle (tout modèle instruction-tuned fonctionne)
ollama pull mistral
# ou : ollama pull llama3, neural-chat, phi3, etc.
```

Wireflux détecte Ollama automatiquement sur `http://127.0.0.1:11434`. Si le processus n'est pas lancé, il tentera de le démarrer automatiquement.

---

### Configuration avancée

Toutes les variables sont optionnelles :

```bash
# Endpoint Ollama (défaut : http://127.0.0.1:11434)
export WIREFLUX_OLLAMA_URL=http://127.0.0.1:11434

# Forcer un modèle spécifique (défaut : auto-détection)
export WIREFLUX_OLLAMA_MODEL=mistral

# Timeout des requêtes en secondes (défaut : 90)
export WIREFLUX_OLLAMA_TIMEOUT_SECS=90

# Nombre max de tokens générés par explication (défaut : 384)
export WIREFLUX_OLLAMA_NUM_PREDICT=384
```

---

### Raccourcis clavier

| Touche | Action |
|--------|--------|
| `Espace` | Démarrer / Arrêter la capture |
| `←` / `→` | Page précédente / suivante |
| `↑` / `↓` | Naviguer entre paquets dans la page |
| `Échap` | Fermer le modal graphe |

---

### Dépannage

| Problème | Solution |
|----------|----------|
| `dumpcap: permission denied` | macOS : exécuter ChmodBPF. Linux : `sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)`. Windows : lancer en Admin |
| Aucune interface listée | Vérifier que Wireshark / dumpcap est installé et dans le PATH |
| Timeout IA | Augmenter `WIREFLUX_OLLAMA_TIMEOUT_SECS`. Les modèles plus petits sont plus rapides |
| Aucun modèle disponible | Lancer `ollama pull mistral` (ou tout autre modèle) |
| Ollama ne démarre pas | Lancer `ollama serve` manuellement et vérifier le port |

---

### Contribuer

Les contributions sont les bienvenues. Avant d'ouvrir une pull request :

1. Exécuter `cargo clippy -- -D warnings` et `cargo fmt`
2. Vérifier que l'app compile avec `npm run tauri build`
3. Garder le côté JS sans dépendances (pas de nouveaux packages npm runtime)
4. Respecter la philosophie du projet dans `AGENTS.md` : **stabilité de capture avant les fonctionnalités**

---

### Licence

> Licence à définir avant la première publication publique.
