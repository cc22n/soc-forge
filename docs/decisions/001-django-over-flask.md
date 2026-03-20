# ADR-001: Django over Flask

## Status: Accepted

## Context

SOC Forge requires 15 interconnected models, user authentication with roles,
an admin interface for data management, and database migrations.

Two frameworks were considered:
- **Flask** (used in the earlier SOC Agent project)
- **Django** (new for this project)

## Decision

We chose Django 5.1 for SOC Forge.

## Rationale

1. **ORM complexity**: 15 models with foreign keys, many-to-many through tables,
   and JSONField. Django ORM handles this natively. Flask + SQLAlchemy would require
   significantly more boilerplate.

2. **Built-in admin**: Django admin provides a free management interface for all models.
   Configured with read-only audit logs, inline editing, and search.

3. **Auth system**: Custom User model with roles, password validation, session management,
   and login/logout views — all built-in with Django.

4. **Migrations**: Django's migration system handles schema evolution cleanly.
   Flask-Migrate works but requires more manual intervention.

5. **Security**: Django's CSRF, XSS protection, and security middleware are battle-tested.

## Consequences

- Steeper learning curve than Flask for simple APIs
- More opinionated structure (apps, settings, urls)
- Django admin is powerful but can become a crutch if overused
- Template engine is less flexible than Jinja2 for complex logic

## Alternatives Considered

- **Flask + SQLAlchemy + Flask-Login + Flask-Migrate**: Would work but requires
  assembling 10+ extensions. Already proven in SOC Agent.
- **FastAPI**: Great for pure APIs but lacks template rendering and admin.
