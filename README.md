# SOC Forge 🔥🛡️

**Customizable Threat Intelligence Investigation Engine for SOC Analysts**

SOC Forge lets security analysts build personalized investigation profiles, query 17 threat intelligence APIs simultaneously, and share findings through a community knowledge base — eliminating the manual API-hopping that wastes hours of analyst time.

---

## The Problem

SOC analysts waste 30-60 minutes per investigation manually checking 10+ threat intelligence platforms, copying data between tabs, and repeating the same lookups their colleagues already did. Enterprise SOAR tools solve this but cost $50K+/year. There's nothing in between.

## The Solution

SOC Forge is a free, self-hosted investigation engine that:

1. **Investigation Profiles** — Define reusable query configurations: which APIs to call, which fields to expect, and in what priority order
2. **One-Click Execution** — Paste any IOC (hash, IP, domain, URL) → select a profile → get unified results from multiple APIs in seconds
3. **Field Normalization** — 244 fields across 17 APIs mapped to a unified taxonomy so `country`, `asn`, and `malware_family` mean the same thing regardless of source
4. **Community Knowledge Base** — Share investigation results so the team never duplicates API calls. Vote to confirm or dispute findings
5. **Full Audit Trail** — Every query, every login, every action tracked with timestamps and IP addresses

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Python 3.12 / Django 5.1 | Mature ORM, built-in admin, battle-tested security |
| Database | PostgreSQL | JSONB for flexible API responses, robust indexing |
| Frontend | Django Templates + Tailwind CSS (CDN) | Server-rendered, fast, no JS framework overhead |
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
┌─────────────────────────────────────────────────────────┐
│                    Django Templates                      │
│              (Tailwind CSS dark theme)                   │
├─────────────────────────────────────────────────────────┤
│                     Django Views                         │
│         users · sources · profiles · investigations      │
│                     · community                          │
├─────────────────────────────────────────────────────────┤
│              Investigation Engine                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │Orchestrator│→│ Registry │→│   17 API Adapters     │  │
│  └──────────┘  └──────────┘  │ VT·AbuseIPDB·Shodan  │  │
│       │                      │ GreyNoise·OTX·...     │  │
│       ▼                      └──────────────────────┘  │
│  ┌──────────┐  ┌──────────┐                            │
│  │Transforms│  │Validators│                            │
│  └──────────┘  └──────────┘                            │
├─────────────────────────────────────────────────────────┤
│                  Django ORM (15 models)                  │
│    User · AuditLog · Source · AvailableField ·          │
│    InvestigationProfile · ProfileSourceConfig ·          │
│    ExpectedField · Indicator · Investigation ·           │
│    InvestigationResult · IndicatorTag ·                  │
│    CommunityIndicator · CommunityResult ·                │
│    CommunityNote · ConfidenceVote                        │
├─────────────────────────────────────────────────────────┤
│                    PostgreSQL                            │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
soc-forge/
├── config/                          # Django settings (base/dev/prod)
│   └── settings/
│       ├── base.py                  # Shared settings + security config
│       ├── development.py           # Debug toolbar, console email
│       └── production.py            # HTTPS, HSTS, secure cookies
├── apps/
│   ├── users/                       # Custom User + AuditLog + middleware
│   │   ├── models.py                # User (with role), AuditLog (immutable)
│   │   ├── middleware.py            # Audit trail for state-changing requests
│   │   └── security_middleware.py   # Rate limiting, input sanitization, headers
│   ├── sources/                     # Threat intel API catalog
│   │   ├── models.py                # Source, AvailableField
│   │   └── management/commands/     # seed_sources (17 APIs + 8 profiles)
│   ├── profiles/                    # Investigation configurations
│   │   └── models.py                # InvestigationProfile, ProfileSourceConfig, ExpectedField
│   ├── investigations/              # Query execution + results
│   │   ├── models.py                # Indicator, Investigation, InvestigationResult, IndicatorTag
│   │   └── engine/                  # ← The core engine
│   │       ├── base_adapter.py      # Abstract adapter with HTTP handling
│   │       ├── transforms.py        # Field normalization functions
│   │       ├── registry.py          # Slug → Adapter mapping
│   │       ├── orchestrator.py      # Full investigation execution
│   │       └── adapters/            # 17 API-specific adapters
│   ├── community/                   # Shared knowledge base
│   │   └── models.py                # CommunityIndicator, CommunityResult, Note, Vote
│   └── core/                        # Shared utilities
│       ├── enums.py                 # IOCType, InvestigationStatus, etc.
│       ├── validators.py            # IOC format validation + auto-detection
│       ├── mixins.py                # TimestampMixin
│       └── exceptions.py            # Domain exceptions
├── templates/                       # Dark SOC-themed UI
└── docs/                            # Architecture docs
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL 14+
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

### First Investigation

1. Go to `http://localhost:8000` → Login
2. Navigate to **Investigations → New Investigation**
3. Paste an IP address: `185.220.101.50`
4. Select **"IP Reputation Check"** profile
5. Click **Execute Investigation**
6. View results from AbuseIPDB, GreyNoise, and ipinfo.io
7. Click **Share to Community** to add to the knowledge base

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| **Brute Force Protection** | django-axes: 5 failed logins → 1 hour lockout |
| **CSRF Protection** | Django CSRF middleware + HttpOnly cookies |
| **Input Sanitization** | Custom middleware blocks XSS, SQLi, path traversal in IOC inputs |
| **Rate Limiting** | 10 investigations/minute per user (in-memory) |
| **Audit Trail** | Immutable AuditLog: who, what, when, IP address |
| **Security Headers** | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Session Security** | HttpOnly, 8-hour expiry, close-on-browser-exit |
| **Password Policy** | Minimum 10 chars, common password check, similarity check |
| **Production HTTPS** | HSTS, secure cookies, SSL redirect (production.py) |

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

## Key Design Decisions

**Why Django over Flask?**
15 interconnected models with complex relationships. Django's ORM, admin, auth, and migrations handle this out of the box. Flask would require assembling the same functionality from 10+ extensions.

**Why PostgreSQL from day one?**
JSONB fields store raw API responses efficiently. Full-text search for the community knowledge base. No SQLite → PostgreSQL migration pain later.

**Why sync API calls instead of Celery?**
Pragmatic choice for a portfolio project. The orchestrator queries APIs sequentially with timeouts. Adding Celery would be the next optimization for production use.

**Why server-rendered templates instead of React/Vue?**
This is a security tool, not a SPA. Server rendering is faster to build, easier to secure (no CORS, no JWT), and Django templates with Tailwind produce a professional UI with less complexity.

---

## What Makes This Different

This isn't a CRUD demo. SOC Forge demonstrates:

- **Domain expertise**: Real SOC analyst workflows, not generic web app patterns
- **Complex data modeling**: 15 models, 20+ relationships, field normalization across 17 APIs
- **Production architecture**: Adapter pattern, orchestrator, registry — not spaghetti code
- **Security-first**: OWASP-aware middleware, immutable audit logs, brute force protection
- **Community collaboration**: Append-only knowledge base with confidence voting

---

## Roadmap

- [ ] Celery + Redis for async API queries
- [ ] STIX/TAXII export for investigation reports
- [ ] LLM-powered analysis summaries (Groq/OpenAI)
- [ ] IOC auto-detection from pasted text blocks
- [ ] Dashboard analytics and investigation trends
- [ ] REST API for programmatic access

---

## Contributing

This is a portfolio project, but PRs are welcome. Please open an issue first to discuss changes.

## License

MIT

---

*Built by [Your Name] — SOC Analyst & Developer*

# soc-forge
