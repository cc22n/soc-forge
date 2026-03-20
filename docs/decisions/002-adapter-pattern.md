# ADR-002: Adapter Pattern for API Integrations

## Status: Accepted

## Context

SOC Forge integrates with 17 different threat intelligence APIs. Each API has:
- Different authentication methods (header, query param, basic auth, body param, none)
- Different request formats (GET, POST with JSON, POST with form data)
- Different response structures
- Different rate limits and error codes

We needed a pattern that makes adding new APIs simple while keeping the
orchestration logic clean.

## Decision

We implemented the **Adapter Pattern** with a common interface:

```python
class BaseAdapter(ABC):
    def query(ioc_value, ioc_type, expected_fields, timeout) -> AdapterResponse
    def _build_request(ioc_value, ioc_type) -> dict  # subclass implements
    def _parse_response(raw, ioc_type, expected_fields) -> list[AdapterResult]  # subclass implements
```

Each API gets its own adapter class. A Registry maps source slugs to adapter classes.
An Orchestrator loops through a profile's sources and calls each adapter.

## Rationale

1. **Separation of concerns**: HTTP handling, error recovery, and timing are in the base.
   API-specific logic is in the subclass. Adding a new API = one new file.

2. **Testability**: Each adapter can be unit-tested independently with mocked responses.

3. **Normalize at the edge**: Each adapter maps raw API fields to normalized names
   using `_collect()`. The orchestrator doesn't know API-specific details.

4. **Graceful degradation**: If one API fails, the orchestrator marks those fields as
   `error` and continues with the next source.

## Consequences

- 17 adapter files to maintain (but each is small, 30-80 lines)
- Some duplication in `_parse_response` methods
- Adding transform functions requires updating both the adapter and transforms.py

## File Structure

```
investigations/engine/
├── base_adapter.py      # BaseAdapter ABC + AdapterResult/Response
├── transforms.py        # Normalization functions (VT ratios, epochs, etc.)
├── registry.py          # ADAPTER_REGISTRY: slug → class
├── orchestrator.py      # InvestigationOrchestrator.run()
└── adapters/
    ├── virustotal.py
    ├── abuseipdb.py
    ├── shodan.py
    ├── greynoise.py
    ├── otx.py
    ├── abusech.py       # ThreatFox + URLhaus + MalwareBazaar
    └── others.py        # SecurityTrails, SafeBrowsing, HybridAnalysis, etc.
```
