-- Runs once, when the Postgres container first creates its data directory.
--
-- The kernel connects as an ordinary role that owns its own database — not as the superuser the
-- image creates. PostgreSQL skips row-level security for superusers, so connecting as one would
-- silently switch the kernel's row-level-security policies off.
CREATE ROLE quaicu_app LOGIN PASSWORD 'quaicu-local' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE quaicu_kernel OWNER quaicu_app;
