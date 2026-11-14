# Evidence Schema

```json
{
  "schema_version": "1.0.0",
  "event_id": "uuid",
  "event_type": "string",
  "node_id": "dg-…",
  "sequence": 1,
  "source_timestamp": 0.0,
  "ingest_timestamp": 0.0,
  "clock_source": "system",
  "target_identity": null,
  "observation": {},
  "tool_identity": "dragon-gate/0.1.0",
  "provenance": {},
  "content_hash": "sha256:…"
}
```

- Source time and ingest time are kept separate.
- `content_hash` covers all fields except itself, using canonical JSON (sorted keys, compact separators).
- NDJSON export is the interchange format; compatible with future BabelCodec normalization.
