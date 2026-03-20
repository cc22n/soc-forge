# ADR-003: Community Knowledge Base Design

## Status: Accepted

## Context

SOC teams waste API calls re-investigating the same IOCs. If analyst A investigates
a suspicious IP at 9am, analyst B shouldn't need to burn API quota checking the same
IP at 10am.

We needed a system where investigation results are optionally shared and trusted.

## Decision

Two-layer data model:

1. **Private layer**: `Investigation` + `InvestigationResult` — owned by the analyst,
   never modified by others
2. **Community layer**: `CommunityIndicator` + `CommunityResult` + `CommunityNote` +
   `ConfidenceVote` — shared, append-only, with confidence voting

Sharing is a conscious action (click "Share to Community"), not automatic.

## Design Rules

- **Original data is immutable**: Once an investigation completes, its results never change
- **Community contributions are append-only**: New data is added, never overwritten
- **Author tracking**: Every contribution records who and when
- **Confidence voting**: Analysts can confirm or dispute shared results
- **No anonymous contributions**: Every data point traces to a user
- **Deduplication**: Same field+source+value is not duplicated when re-shared

## Data Flow

```
Analyst runs investigation
    → InvestigationResult saved (private)
    → Analyst clicks "Share to Community"
        → CommunityIndicator created (or updated count)
        → CommunityResult entries created (deduped)
        → Other analysts can view, vote, add notes
```

## Consequences

- Slight data duplication between Investigation and Community layers (by design)
- No automatic freshness — stale data is visible until re-investigated
- Voting system is simple (confirm/dispute) — could evolve to weighted trust scores
