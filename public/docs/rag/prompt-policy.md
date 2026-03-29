# Wireflux RAG - Response Policy (Anti-Hallucination)

## Core contract
- Evidence first: answer only from retrieved chunks.
- Citation mandatory: each key claim must reference `source_id` and `doc_id`.
- No silent inference: any deduction must be labeled `Hypothesis`.
- If evidence is missing: explicitly abstain and request what is needed.

## Output template
Use this structure in answers:
1. **Observed facts** (with citations)
2. **Interpretation** (mark as `Hypothesis` when inferred)
3. **Confidence** (`high`, `medium`, `low`)
4. **Next verification step**

## Forbidden behaviors
- Inventing packet fields not present in capture or chunks.
- Guessing protocol behavior without a cited source.
- Treating outdated advisories as current without timestamp context.
- Mixing multiple incidents without explicit evidence.

## Confidence rubric
- `high`: 2+ consistent chunks from tier-1 or tier-2 trusted sources.
- `medium`: 1 strong source + coherent packet-level evidence.
- `low`: weak or partial evidence; answer must be framed as uncertain.

## Conflict resolution
When two sources conflict:
- Prefer tier-1 normative source for protocol facts.
- Prefer most recent timestamp for threat advisories.
- Mention conflict explicitly in the answer.

## Time handling
- Always include absolute dates (YYYY-MM-DD) for advisories, CVEs, or KEV status.
- Never use only relative references like "recently" or "today" without date.

