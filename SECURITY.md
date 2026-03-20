# Security Policy — SOC Forge

## Security Architecture

SOC Forge handles sensitive threat intelligence data and API credentials.
Security is implemented as defense-in-depth across multiple layers.

### Authentication & Authorization

- **Custom User model** with role-based access (Analyst, Admin)
- **django-axes**: Locks accounts after 5 failed login attempts for 1 hour
- **Password policy**: Minimum 10 characters, common password rejection, similarity check
- **Session management**: HttpOnly cookies, 8-hour expiry, expire on browser close

### Input Validation

- **IOC validators**: Format validation for MD5, SHA1, SHA256, IPv4, IPv6, domain, URL
- **Auto-detection**: Identifies IOC type from raw input to prevent type confusion
- **Sanitization middleware**: Blocks XSS, SQL injection, path traversal, and command injection patterns in IOC inputs
- **Django CSRF**: All state-changing requests require CSRF tokens

### Rate Limiting

- **Investigation queries**: 10 per minute per authenticated user (in-memory)
- **Login attempts**: 5 failures → 1 hour lockout (django-axes)
- **API rate limits**: Per-source limits enforced by the adapter layer

### Security Headers

Applied via `SecurityHeadersMiddleware`:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`
- `Cache-Control: no-store` (for authenticated pages)

### Audit Trail

The `AuditMiddleware` records all state-changing requests:

- **Who**: User ID and username
- **What**: Action type (login, create, update, delete, share)
- **When**: Timestamp
- **Where**: IP address, request path

Audit logs are **immutable**: the Django admin prevents creation, modification, and deletion.

### API Key Management

- All API keys stored in `.env` file (never committed to version control)
- `.env.example` provides a template without real values
- Keys accessed via `django-environ` through `settings.THREAT_INTEL_KEYS`
- No API keys are ever exposed in logs or error messages

### Production Hardening (production.py)

When deployed with `DJANGO_SETTINGS_MODULE=config.settings.production`:

- `SECURE_SSL_REDIRECT = True`
- `SECURE_HSTS_SECONDS = 31536000` (1 year)
- `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
- `SECURE_HSTS_PRELOAD = True`
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`

## Reporting Vulnerabilities

If you discover a security vulnerability, please open a private issue or contact the maintainer directly. Do not open a public issue for security vulnerabilities.

## Threat Model

SOC Forge is designed for deployment on a trusted internal network. The primary threats considered are:

1. **Credential stuffing** → Mitigated by django-axes lockout
2. **XSS via malicious IOC values** → Mitigated by input sanitization + Django auto-escaping
3. **API key exposure** → Mitigated by .env isolation + .gitignore
4. **Unauthorized data access** → Mitigated by per-user investigation filtering
5. **Audit log tampering** → Mitigated by immutable admin configuration
