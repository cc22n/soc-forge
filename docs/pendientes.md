# SOC Forge — Trabajo Pendiente
> Estado al 2026-05-17. Actualizar con [x] al completar cada ítem.
>
> **✅ ARCHIVO CERRADO (2026-07-07):** Todo lo listado aquí fue completado y commiteado
> en `e3bb3ef` (security hardening + fixes de adaptadores TASK-019 a 024) y
> `0306a61` (IPGeolocation TASK-025 a 028). La migración `0006` está aplicada.
> Se conserva solo como referencia histórica; la sección 2.2 (limitaciones de
> planes gratuitos) sigue siendo información operativa útil.

---

## 1. Cambios sin commitear (del agente anterior)

Hay 15 archivos modificados y 1 migración nueva sin aplicar. Todos los cambios son mejoras de seguridad y calidad de código.

### Migración pendiente de aplicar

- [x] `python manage.py migrate` — aplicar `users.0006_username_ci_unique`
  - Agrega constraint CI (case-insensitive) de unicidad para `username`
  - Aplicada (confirmado con `showmigrations users`)

### Cambios para commitear

| Archivo | Qué cambió |
|---------|------------|
| `apps/users/models.py` | Constraint CI username + `select_for_update()` en AuditLog |
| `apps/users/security_middleware.py` | Límite 2048 chars en IOC, imports en top-level |
| `apps/core/utils.py` | `get_client_ip()` usa solo `REMOTE_ADDR` (evita IP spoofing) |
| `apps/core/mixins.py` | Fix bug `analyst_id is None` → AttributeError |
| `apps/investigations/views.py` | Escape `'` en STIX, mitigación prompt injection LLM, fix doble query |
| `apps/api/views.py` | try/except en `int(limit)` para params malformados |
| `apps/investigations/engine/adapters/others.py` | API key SafeBrowsing fuera de URL, URL encoding IPQualityScore |
| `apps/investigations/llm.py` | Client cache + timeout 30s |
| `apps/investigations/tasks.py` | `transaction.atomic()` en Indicator+Investigation |
| `tests/test_views.py` | 8 tests nuevos para `/investigations/{id}/summary/` |
| `apps/users/views.py`, `apps/users/security_middleware.py`, etc. | Logging `%s` en vez de f-strings |

**Estado de tests:** 140/140 ✅

---

## 2. Problemas en Adaptadores de API — PRIORIDAD ALTA

El orquestador corre adaptadores en paralelo con `ThreadPoolExecutor(max_workers=8)` y timeout global de 90s. Los problemas abajo causan que algunas fuentes siempre fallen con "error" en lugar de "sin datos".

### 2.1 Bugs confirmados

| # | Adaptador | Bug | Impacto |
|---|-----------|-----|---------|
| **B1** | Todos (key vacía) | API key vacía → 401 HTTP → `SourceUnavailableError` en log como ERROR | APIs no configuradas llenan logs de errores falsos |
| **B2** | GreyNoise | IP no conocida devuelve HTTP 404 → tratado como error, debería ser "sin datos" | Muchas IPs legítimas no están en GreyNoise → falso error |
| **B3** | Shodan | IP no escaneada devuelve HTTP 404 → tratado como error | IPs nuevas/privadas no están en Shodan → falso error |
| **B4** | SecurityTrails | Dominio no en base → HTTP 404 → error | Dominios nuevos no están en SecurityTrails → falso error |
| **B5** | OTX (URL type) | `ioc_value` no se URL-encoda en el path → falla con `http://example.com/path?q=1` | URLs con `/`, `?`, `&` rompen el endpoint |
| **B6** | HybridAnalysis | `SUPPORTED_IOC_TYPES = ["hash", "url"]` pero `_build_request` usa endpoint de hashes para URLs | Análisis de URLs siempre busca hash, devuelve datos incorrectos o 404 |

### 2.2 Limitaciones de plan gratuito (no bugs, info operativa)

| Adaptador | Limitación |
|-----------|------------|
| **IPInfo** | `privacy.vpn/proxy/tor` son campos de plan pago — siempre `NOT_FOUND` en free |
| **Shodan** | `vulns` requiere plan pago — siempre `NOT_FOUND` en free |
| **CriminalIP** | Casi todo requiere créditos — free muy limitado |
| **Pulsedive** | Rate limit 1/min muy agresivo — timeout frecuente |
| **SecurityTrails** | Rate limit 1/min — timeout frecuente |
| **GreyNoise** | Community endpoint — datos limitados vs API full |
| **URLScan** | Solo retorna scans existentes, no hace scan nuevo — vacío si nunca fue escaneado |

### 2.3 Fixes implementados (TASK-019 a TASK-024)

- [x] **TASK-019** — `REQUIRES_API_KEY` en BaseAdapter — saltar fuente si key vacía, sin error
- [x] **TASK-020** — `NOT_FOUND_IS_VALID` en BaseAdapter — tratar HTTP 404 como "sin datos" no como error
- [x] **TASK-021** — Aplicar `NOT_FOUND_IS_VALID = True` en GreyNoise, Shodan, SecurityTrails
- [x] **TASK-022** — Aplicar `REQUIRES_API_KEY = False` en ThreatFox, URLhaus, Malware Bazaar
  - Nota: en `abusech.py` la clase base terminó con `REQUIRES_API_KEY = True` porque abuse.ch
    hizo la autenticación obligatoria en 2025 (posterior a este plan) — divergencia intencional,
    no bug pendiente.
- [x] **TASK-023** — Fix OTX: URL-encodar `ioc_value` para type `url`
- [x] **TASK-024** — Fix HybridAnalysis: remover `url` de `SUPPORTED_IOC_TYPES`

---

## 3. Integración IPGeolocation (Nueva Feature)

El archivo `integrar-ipgeolocation-plan-gratis.md` documenta la integración pendiente.

**Plan gratuito:** 1000 créditos/día, sin tarjeta. Endpoint: `https://api.ipgeolocation.io/v3/ipgeo`

- [x] **TASK-025** — Crear `IPGeolocationAdapter` en `adapters/others.py`
  - `SOURCE_SLUG = "ipgeolocation"`, `SUPPORTED_IOC_TYPES = ["ip"]`
  - Campos: `country`, `city`, `region`, `latitude`, `longitude`, `org`, `asn`, `time_zone`, `currency`
  - `env_var_name = "IPGEOLOCATION_API_KEY"`
- [x] **TASK-026** — Registrar adaptador en `registry.py`
- [x] **TASK-027** — Agregar fuente en `_sources_part3.py` y ejecutar `seed_sources` (fuente #18, 10 campos)
- [x] **TASK-028** — Agregar key en `.env.example` y settings

---

## 4. Commit y Cierre

- [x] Aplicar migración `0006`
- [x] `git add` de todos los archivos modificados
- [x] Crear commit con todos los cambios del agente anterior + fixes de adaptadores
  (`e3bb3ef`, `0306a61`)
- [x] Opcional: eliminar archivos MD de plan del repo raíz (moverlos a `docs/`)

---

## 5. Panel de Salud de Adaptadores (Nueva Feature)

Dashboard admin-only en `/sources/health/` que agrega found/not_found/error+timeout y latencia
promedio (30 días) por fuente, incluyendo fuentes que no dejaron ninguna fila de
`InvestigationResult` (key faltante, drop por timeout global) — antes desaparecían del widget
de performance del dashboard en vez de mostrarse como "sin datos".

- [x] **TASK-029** — Vista `source_health()` en `apps/sources/views.py`, gateada con
  `user_passes_test(lambda u: u.is_admin)` (primer uso de rol en una vista del proyecto)
- [x] **TASK-030** — Ruta `sources:health` en `apps/sources/urls.py`
- [x] **TASK-031** — Template `templates/sources/health.html` + link en sidebar (`base.html`,
  visible solo para `user.is_admin`)
- [x] **TASK-032** — Tests (`tests/test_sources_health.py`, 7 casos): gate de rol, fuente sin
  datos → `no_data`, mayoría de errores → `down`, mayoría de `not_found` → sigue `healthy`

**Estado de tests:** 180/180 ✅ (173 previos + 7 nuevos)
**Commit:** `8081b9b` — pusheado a `origin/main`

---

## Resumen de Progreso General

| Fase | Estado |
|------|--------|
| Fase 1 — Impacto Inmediato | ✅ Completada |
| Fase 2 — Calidad y Seguridad | ✅ Completada |
| Fase 3 — Escalabilidad | ✅ Completada |
| Fase 4 — API y Automatización | ✅ Completada |
| Fixes de Adaptadores (TASK-019 a 024) | ✅ Completada |
| Integración IPGeolocation (TASK-025 a 028) | ✅ Completada |
| Migración + Commit | ✅ Completada |
| Panel de Salud de Adaptadores (TASK-029 a 032) | ✅ Completada |
