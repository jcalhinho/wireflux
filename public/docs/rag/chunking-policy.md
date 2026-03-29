# Wireflux RAG - Chunking Policy

## Objective
Create high-signal chunks for packet analysis answers while keeping citations precise and auditable.

## Rules (default)
- Chunk size target: 500 to 900 characters.
- Chunk overlap: 80 to 140 characters.
- Hard max per chunk: 1400 characters.
- Keep section boundaries when available.
- Never merge unrelated protocols in one chunk.

## Source-specific strategy
- RFC / standards: split by section/subsection titles.
- Registries (IANA tables): one chunk per semantic table block.
- Security advisories: one chunk per vulnerability/advisory item.
- Technique catalogs (ATT&CK): one chunk per technique, plus one for detection guidance.

## Metadata requirements
Each chunk must include:
- `source_id`
- `doc_id`
- `source_url`
- `title`
- `section`
- `retrieved_at`
- `tags`
- `confidence_level`

## Tagging baseline
- Protocol tags: `tcp`, `udp`, `icmp`, `dns`, `tls`, `http`, `arp`, `ipv4`, `ipv6`
- Layer tags: `l2`, `l3`, `l4`, `l5`, `l6`, `l7`
- Security tags: `scan`, `bruteforce`, `beaconing`, `exfiltration`, `cve`, `mitre`

## Quality gates before indexing
- No empty or duplicate chunks.
- No chunk without source URL.
- No chunk with unresolved extraction artifacts.
- Hash-based deduplication enabled.
- Timestamp of ingestion stored.

## Refresh cadence
- Tier 1 normative sources: every 30 days.
- Tier 2 security advisories and vulnerabilities: daily.
- Tier 3 support docs: every 30 days.

