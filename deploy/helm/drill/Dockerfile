# N11-P02-T04/T05 HA failover drill image.
#
# Patroni is the documented reference HA manager (deploy/helm/yabanin/HA-TOPOLOGY.md,
# Tier 2 / I41). The raft DCS is Patroni's built-in consensus, so the drill needs no
# external DCS service. Everything is pinned: base image, Patroni, psycopg driver.
#
# Drill-only: the image runs as the postgres user (non-root, container policy) and
# carries no application code or credentials.
FROM postgres:16-alpine

ARG PATRONI_VERSION=4.1.5
ARG PSYCOPG_VERSION=3.3.6

RUN apk add --no-cache python3 py3-pip \
 && pip install --no-cache-dir --break-system-packages \
      "patroni[raft]==${PATRONI_VERSION}" \
      "psycopg[binary]==${PSYCOPG_VERSION}" \
 && mkdir -p /pgdata /etc/patroni-drill \
 && chown -R postgres:postgres /pgdata /etc/patroni-drill

USER postgres
ENV PGDATA=/pgdata/pg
CMD ["patroni", "/etc/patroni-drill/patroni.yml"]
