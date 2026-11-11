# Database migrations

Alembic migrations for the kernel's PostgreSQL tables. Run them once before first start on any
configuration that uses the Postgres adapters:

```
DATABASE_URL=postgresql://user:pass@host/db \
    alembic -c quaicu/adapters/storage/migrations/alembic.ini upgrade head
```

Connect as an ordinary role that owns the database, not as a PostgreSQL superuser: superusers
(and roles with `BYPASSRLS`) are exempt from row-level security, which would silently disable the
kernel's tenant-isolation policies. `docker/postgres-init.sql` shows the two statements needed.

The revision numbers are not contiguous (001–004, 007, 012–014, 016, 017). The gaps are revisions
that belong to a separately maintained hosted service and are not part of this project; the chain
here is complete on its own.
