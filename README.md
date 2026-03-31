# SOC Forge

**Customizable Threat Intelligence Investigation Engine for SOC Analysts**

SOC Forge lets security analysts build personalized investigation profiles, query 17 threat intelligence APIs simultaneously, and share findings through a community knowledge base — eliminating the manual API-hopping that wastes hours of analyst time.

---

## The Problem

SOC analysts waste 30-60 minutes per investigation manually checking 10+ threat intelligence platforms, copying data between tabs, and repeating the same lookups their colleagues already did. Enterprise SOAR tools solve this but cost $50K+/year. There's nothing in between.

## The Solution

SOC Forge is a free, self-hosted investigation engine that:

1. **Investigation Profiles** — Define reusable query configurations: which APIs to call, which fields to expect, and in what priority order
2. **Parallel Execution** — Paste any IOC (hash, IP, domain, URL) → select a profile → all APIs queried concurrently via `ThreadPoolExecutor`, results in seconds
3. **Field Normalization** — 244 fields across 17 APIs mapped to a unified taxonomy so `country`, `asn`, and `malware_family` mean the same thing regardless of source
4. **DB-Level Result Cache** — Reuses recent `InvestigationResult` records within each source's TTL window, avoiding redundant API calls across restarts and workers
5. **Community Knowledge Base** — Share investigation results so the team never duplicates API calls. Vote to confirm or dispute findings
6. **Full Audit Trail** — Every query, every login, every action tracked with SHA-256 cryptographic chain (blockchain-style tamper detection)
7. **LLM Summaries** — One click generates a natural-language summary and action recommendation; supports Anthropic, OpenAI, Groq, xAI Grok, and Google Gemini — swap providers via a single `.env` variable
8. **Landing Page + Registration** — Public landing page for new visitors; secure self-registration with IP rate limiting, password strength enforcement, and brute-force protection

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Python 3.12 / Django 5.1 | Mature ORM, built-in admin, battle-tested security |
| Database | PostgreSQL | JSONB for flexible API responses, robust indexing |
| Frontend | Django Templates + Tailwind CSS (CDN) | Server-rendered, fast, no JS framework overhead |
| Task Queue | Celery + Redis | Async investigation dispatch with priority queues |
| REST API | Django REST Framework | Token-authenticated programmatic access |
| LLM | Anthropic · OpenAI · Groq · xAI · Gemini | Natural-language summaries — provider swappable via `.env` |
| Security | django-axes, CSP headers, audit middleware | OWASP-aware from day one |
| APIs | 17 threat intelligence sources | Real integrations, not mocks |

---

## Supported Intelligence Sources (17)

| Source | IOC Types | Auth | Rate Limit |
|--------|----------|------|------------|
| **VirusTotal** | Hash, IP, Domain, URL | API Key | 4/min |
| **AbuseIPDB** | IP | API Key | 17/min |
| **Shodan** | IP | API Key | 1/min |
| **GreyNoise** | IP | API Key | 1/min |
| **AlienVault OTX** | Hash, IP, Domain, URL | API Key | 167/min |
| **Google Safe Browsing** | URL, Domain | API Key | 167/min |
| **Hybrid Analysis** | Hash, URL | API Key | 3/min |
| **SecurityTrails** | Domain, IP | API Key | 1/min |
| **ThreatFox** | Hash, IP, Domain | Free | 10/min |
| **URLhaus** | URL, Domain, Hash | Free | 10/min |
| **URLScan.io** | URL, Domain | API Key | 2/min |
| **Pulsedive** | IP, Domain, Hash, URL | API Key | 1/min |
| **Criminal IP** | IP | API Key | 1/min |
| **IPQualityScore** | IP, URL | API Key | 3/min |
| **Censys** | IP, Domain | Basic Auth | 4/min |
| **Malware Bazaar** | Hash | Free | 10/min |
| **ipinfo.io** | IP | API Key | 833/min |

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Django Templates                         │
│              (Tailwind CSS dark theme)                      │
├────────────────────────────────────────────────────────────┤
│              Django REST Framework (apps/api/)              │
│    TokenAuth · Investigations · Community · Status poll     │
├────────────────────────────────────────────────────────────┤
│                     Django Views                            │
│      users · sources · profiles · investigations · community│
├────────────────────────────────────────────────────────────┤
│          Celery Task Queue (Redis broker)                   │
│   high_priority (≤3 sources) · full_investigation          │
│              ↓ fallback to sync if unavailable             │
├────────────────────────────────────────────────────────────┤
│              Investigation Engine                           │
│  ┌──────────────┐  ┌──────────┐  ┌──────────────────────┐ │
│  │ Orchestrator  │→│ Registry │→│   17 API Adapters      │ │
│  │(ThreadPool)   │  └──────────┘  │ VT·AbuseIPDB·Shodan  │ │
│  └──────────────┘                 │ GreyNoise·OTX·...    │ │
│         │  ↑ DB cache check       └──────────────────────┘ │
│         ▼  (TTL per source)                                 │
│  ┌──────────┐  ┌──────────┐                                │
│  │Transforms│  │Validators│                                │
│  └──────────┘  └──────────┘                                │
├────────────────────────────────────────────────────────────┤
│                  Django ORM (17 models)                     │
│    User · Organization · UserReputation · AuditLog ·        │
│    Source · AvailableField · InvestigationProfile ·         │
│    ProfileSourceConfig · ExpectedField · Indicator ·        │
│    Investigation · InvestigationResult · IndicatorTag ·     │
│    CommunityIndicator · CommunityResult ·                   │
│    CommunityNote · ConfidenceVote                           │
├────────────────────────────────────────────────────────────┤
│                    PostgreSQL                               │
│   GIN indexes · B-tree indexes · JSONB · full-text search  │
└────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
soc-forge/
├── config/
│   ├── celery.py                    # Celery app with autodiscover
│   ├── settings/
│   │   ├── base.py                  # Shared settings + security + DRF + Celery
│   │   ├── development.py           # Debug toolbar, console email
│   │   └── production.py            # HTTPS, HSTS, secure cookies
│   └── urls.py                      # Root URL conf (includes /api/)
├── apps/
│   ├── users/                       # Custom User + AuditLog + middleware
│   │   ├── models.py                # User, Organization, UserReputation, AuditLog (crypto chain)
│   │   ├── middleware.py            # Audit trail for state-changing requests
│   │   └── security_middleware.py   # Rate limiting (Redis/LocMem), sanitization, headers
│   ├── sources/                     # Threat intel API catalog
│   │   ├── models.py                # Source (with TTL), AvailableField
│   │   └── management/commands/     # seed_sources (17 APIs + 8 profiles)
│   ├── profiles/                    # Investigation configurations
│   │   └── models.py                # InvestigationProfile, ProfileSourceConfig, ExpectedField
│   ├── investigations/              # Query execution + results
│   │   ├── models.py                # Indicator, Investigation, InvestigationResult (schema_version)
│   │   ├── tasks.py                 # Celery shared_task + dispatch_investigation()
│   │   └── engine/                  # ← The core engine
│   │       ├── base_adapter.py      # Abstract adapter (AdapterResponse with source_slug)
│   │       ├── transforms.py        # Field normalization functions
│   │       ├── registry.py          # Slug → Adapter mapping
│   │       ├── orchestrator.py      # Parallel execution (ThreadPoolExecutor) + DB cache
│   │       └── adapters/            # 17 API-specific adapters
│   ├── api/                         # REST API (DRF)
│   │   ├── serializers.py           # 6 serializers
│   │   ├── views.py                 # 5 endpoints with TokenAuthentication
│   │   └── urls.py                  # /api/ URL patterns
│   ├── community/                   # Shared knowledge base
│   │   └── models.py                # CommunityIndicator, CommunityResult, Note, Vote
│   └── core/                        # Shared utilities
│       ├── enums.py                 # IOCType, InvestigationStatus, etc.
│       ├── validators.py            # IOC validation + private IP blocking
│       ├── mixins.py                # org_investigations_filter, user_can_access_investigation
│       └── exceptions.py            # Domain exceptions
│   │   ├── llm.py                   # Multi-provider LLM abstraction (Anthropic/OpenAI/Groq/Grok/Gemini)
│   │   └── engine/                  # ← The core engine
├── templates/
│   ├── home.html                    # Public landing page
│   ├── registration/
│   │   ├── login.html               # Sign-in form
│   │   └── register.html            # Self-registration form
│   └── …                           # Dark SOC-themed UI
└── tests/                           # 132 tests (pytest-django)
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL 14+
- Redis (optional — falls back to sync execution without it)
- At least one threat intelligence API key (free options: ThreatFox, URLhaus, Malware Bazaar)

### Installation

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/soc-forge.git
cd soc-forge

# Virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Dependencies
pip install -r requirements.txt

# Environment
cp .env.example .env
# Edit .env with your SECRET_KEY, DATABASE_URL, and API keys

# Database
python manage.py migrate
python manage.py createsuperuser

# Seed intelligence sources (17 APIs + 8 default profiles)
python manage.py seed_sources --profiles

# Run
python manage.py runserver
```

### Optional: Celery for async investigations

```bash
# In a separate terminal
celery -A config worker -l info -Q high_priority,full_investigation,celery
```

### Optional: LLM summaries

Set one provider in `.env` (only the matching key is needed):

```env
# Anthropic Claude (default)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI ChatGPT
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Groq — fast, free tier available
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...

# xAI Grok
LLM_PROVIDER=grok
GROK_API_KEY=xai-...

# Google Gemini
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIza...

# Override the model for any provider (optional)
LLM_MODEL=llama-3.1-8b-instant
```

### First Investigation

1. Go to `http://localhost:8000` — landing page for new visitors
2. Click **Create Account** to register, or **Sign In** if you already have an account
3. Navigate to **Investigations → New Investigation**
4. Paste an IP address: `185.220.101.50`
5. Select **"IP Reputation Check"** profile
6. Click **Execute Investigation**
7. View results from AbuseIPDB, GreyNoise, and ipinfo.io — each source shows an OK/Partial/Error badge
8. Click **Generar resumen** to get an AI-powered analysis (requires an LLM key in `.env`)
9. Click **Share to Community** to add to the knowledge base

---

## REST API

Authenticate with a DRF token (`Authorization: Token <token>`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/investigations/` | Start a new investigation |
| `GET` | `/api/investigations/{id}/` | Get investigation + results |
| `GET` | `/api/investigations/{id}/status/` | Poll async status |
| `GET` | `/api/community/` | Browse community IOCs |
| `POST` | `/api/token/` | Obtain auth token |

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| **Brute Force Protection** | django-axes: 5 failed logins → 1 hour lockout |
| **CSRF Protection** | Django CSRF middleware + HttpOnly cookies — logout uses POST, not GET |
| **Input Sanitization** | Custom middleware blocks XSS, SQLi, path traversal in IOC inputs |
| **Private IP Blocking** | Validator rejects RFC1918, loopback, link-local, multicast (IPv4 + IPv6) |
| **Rate Limiting** | Redis-backed atomic counters (LocMemCache fallback) — covers both investigations and registration |
| **Registration Security** | IP rate limit (5 attempts/10 min), username allowlist `[a-zA-Z0-9_-]`, email uniqueness, Django password validators |
| **Cryptographic Audit Trail** | SHA-256 chain in AuditLog — `verify_chain()` detects any tampered entry |
| **Security Headers** | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Session Security** | HttpOnly, 8-hour expiry, close-on-browser-exit |
| **Password Policy** | Minimum 10 chars, common password check, similarity check |
| **Production HTTPS** | HSTS, secure cookies, SSL redirect (production.py) |
| **Multi-tenant Isolation** | Organization model + Q-filter helpers scope all investigation queries |

---

## Default Investigation Profiles

| Profile | IOC Type | Sources | Use Case |
|---------|----------|---------|----------|
| Quick Hash Lookup | Hash | VT, MalwareBazaar | Fast malware check |
| Full Malware Analysis | Hash | VT, MalwareBazaar, HybridAnalysis, ThreatFox, OTX | Deep hash investigation |
| IP Reputation Check | IP | AbuseIPDB, GreyNoise, ipinfo | Quick IP triage |
| Infrastructure Recon | IP | Shodan, Censys, CriminalIP | Port/service/vuln scan |
| Full IP Investigation | IP | 9 sources | Complete IP analysis |
| Domain Investigation | Domain | VT, SecurityTrails, OTX, URLScan, SafeBrowsing | Domain triage |
| Phishing URL Analysis | URL | VT, URLScan, SafeBrowsing, IPQS, OTX | Phishing detection |
| Malware Delivery URL | URL | URLhaus, VT, URLScan, HybridAnalysis | Malware URL check |

---

## Improvement Plan — Completed (18/18 tasks)

The project went through a structured 4-phase improvement plan after the initial build:

### Phase 1 — Immediate Impact
- **Parallel API execution** — `ThreadPoolExecutor(max_workers=8)` in the orchestrator; DB prep and `bulk_create` stay in the main thread to avoid ORM threading issues
- **`source_slug` on `AdapterResponse`** — adapters now self-identify in parallel results
- **Private IP validation** — rejects RFC1918, loopback, link-local, multicast, and IPv6 reserved ranges
- **Redis-backed rate limiting** — `caches["rate_limit"]` with atomic `add()`+`incr()`; LocMemCache fallback for dev/test
- **Per-source status badges** — each source panel shows OK / Partial / Error / No data

### Phase 2 — Data Quality and Security
- **DB-level result cache** — before any API call, checks `InvestigationResult` records within the source's TTL; copies results on hit, calls API on miss
- **`schema_version` field** — future-proof field migrations on `InvestigationResult`
- **TTL-aware community deduplication** — stale community entries get refreshed; recent ones are skipped
- **Cryptographic audit chain** — `AuditLog.save()` computes SHA-256 over the previous entry's hash; `verify_chain()` returns the first broken link

### Phase 3 — Scalability and Multi-tenancy
- **Performance indexes** — `idx_inv_results_source_fetched` (orchestrator cache), `idx_investigations_indicator`, `idx_community_results_dedup`, `idx_audit_log_detail_gin` (GIN), `idx_audit_log_entry_hash`
- **Organization model** — nullable FK on `User`; `org_investigations_filter()` and `user_can_access_investigation()` scope all queries
- **User reputation system** — `UserReputation` with `trust_weight` (0.1× new → 1.0× verified); throttle at 30 shares/hour; dispute penalty −10 points
- **STIX 2.1 export** — `GET /investigations/{id}/export/stix/` downloads a spec-compliant Bundle JSON with `indicator` + `observed-data` objects per source

### Phase 4 — REST API and Automation
- **REST API** — `apps/api/` with DRF `TokenAuthentication`; 5 endpoints for investigations, community, and status polling
- **Analytics dashboard** — PostgreSQL aggregations (`Avg`, `Count`, `TruncDate`, `F`); IOC breakdown bars, source performance table (found rate + avg ms), top IOCs
- **Celery async dispatch** — `run_investigation_task` shared task with retry; `dispatch_investigation()` selects `high_priority` (≤3 sources) or `full_investigation` queue; sync fallback if Redis unavailable
- **LLM summaries** — `POST /investigations/{id}/summary/` → JSON `{summary, recommendation, provider}`; provider-agnostic `apps/investigations/llm.py` module dispatches to Anthropic, OpenAI, Groq, xAI, or Gemini based on `LLM_PROVIDER` in `.env`; UI panel shows which model generated the response

---

## Key Design Decisions

**Parallel execution without async Django**
`ThreadPoolExecutor` keeps HTTP calls off the main thread while all DB operations (ORM queries, `bulk_create`) stay in the main thread. This avoids Django ORM threading issues without requiring async views or ASGI.

**DB cache instead of Redis cache**
Reusing existing `InvestigationResult` rows within each source's TTL avoids adding a Redis dependency for caching. It survives restarts, works across multiple workers, and keeps the audit trail intact.

**Cryptographic audit log**
Each `AuditLog` entry stores the SHA-256 of the previous entry's hash, creating a tamper-evident chain. `verify_chain()` can detect if any historical record was altered.

**Organization isolation with nullable FK**
Solo users can keep using the system without belonging to an org. Q-filter helpers (`org_investigations_filter`) handle both cases transparently in every view.

**STIX 2.1 without external library**
The spec is straightforward enough to implement manually for the subset needed (indicator + observed-data). No `stix2` dependency means one less supply-chain risk.

**Celery with sync fallback**
`dispatch_investigation()` catches the Celery/Redis connection error and falls back to synchronous execution. The app works in dev without Redis running.

**Multi-provider LLM with one package**
Groq, xAI (Grok), and Gemini all expose OpenAI-compatible REST APIs, so the `openai` SDK covers all three by switching `base_url`. Only Anthropic needs its own SDK. Changing provider is a one-line `.env` edit — no code changes required.

**Landing page at root, dashboard behind auth**
`/` serves a public landing page; authenticated users are redirected to `/dashboard/`. This separates marketing/onboarding from the authenticated app without duplicating templates.

**Why Django over Flask?**
17 interconnected models with complex relationships. Django's ORM, admin, auth, and migrations handle this out of the box.

**Why PostgreSQL from day one?**
JSONB fields store raw API responses efficiently. GIN indexes enable fast JSON key searches. No SQLite → PostgreSQL migration pain later.

**Why server-rendered templates instead of React/Vue?**
This is a security tool, not a SPA. Server rendering is faster to build, easier to secure (no CORS, no JWT), and Django templates with Tailwind produce a professional UI with less complexity.

---

## Contributing

This is a portfolio project, but PRs are welcome. Please open an issue first to discuss changes.

## License

MIT
