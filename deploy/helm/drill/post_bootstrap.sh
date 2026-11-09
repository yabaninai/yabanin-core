#!/bin/sh
# Runs once on the bootstrap leader with the new cluster's connection string
# as $1 (Patroni bootstrap.post_bootstrap contract). Creates the drill roles
# and database:
#
#   drill_app     — the quorum path (I44 accounting/authorization/audit):
#                   commits acknowledge only after the synchronous standby
#                   has received the WAL (Patroni synchronous_mode).
#   drill_history — the default history path (I44): commits with
#                   synchronous_commit=off (async), loss bounded by contract
#                   (RPO <= 60 s default; never RPO=0).
#
# No passwords: trust-authenticated drill network (isolated, no published
# ports). Production installs create roles out-of-band.
set -e
i=0
until psql "$1" -Atqc 'SELECT 1' >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -ge 30 ] && { echo "post_bootstrap: server never accepted queries"; exit 2; }
  sleep 1
done
psql "$1" -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE drill_app LOGIN;
CREATE ROLE drill_history LOGIN;
ALTER ROLE drill_history SET synchronous_commit = off;
CREATE DATABASE drill OWNER drill_app;
\c drill
GRANT USAGE, CREATE ON SCHEMA public TO drill_app, drill_history;
SQL
