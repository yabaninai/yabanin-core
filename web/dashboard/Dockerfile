# Standalone dashboard image. Build from the REPO ROOT (the dashboard
# imports design tokens from the shared design/ directory):
#   docker build -f web/dashboard/Dockerfile -t yabanin-dashboard .
# node:20-alpine digest-pinned 2026-10-25 via `docker buildx imagetools inspect` (relprep §9 follow-up)
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS builder
# WORKDIR mirrors the repo layout (…/web/dashboard with ../design and
# ../scripts/web) so `npm run build` can run scripts/web/bundle_budget.mjs
# via its repo-root-relative path (R077-02).
WORKDIR /src/web/dashboard
COPY web/dashboard/package*.json ./
RUN npm ci
COPY web/dashboard .
COPY design /design
COPY scripts/web/bundle_budget.mjs ../../scripts/web/bundle_budget.mjs
RUN npm run build

# Serve stage
# nginx:alpine digest-pinned 2026-10-25 via `docker buildx imagetools inspect` (relprep §9 follow-up)
FROM nginx:alpine@sha256:713fc2ebfd92e8217db451477182ee91944b123d2b1ee9fd5a8c6e91ca6c3a11
COPY --from=builder /src/web/dashboard/dist /usr/share/nginx/html
COPY web/dashboard/nginx-main.conf /etc/nginx/nginx.conf
COPY web/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
# nginx creates only the last path component itself; pre-create the /tmp
# temp trees writable by the unprivileged runtime user (nobody:nogroup).
RUN mkdir -p /tmp/nginx/client /tmp/nginx/proxy /tmp/nginx/fastcgi     /tmp/nginx/uwsgi /tmp/nginx/scgi     && chown -R nobody:nogroup /tmp/nginx
# Unprivileged listener (nginx.conf listens on 8080; USER nobody cannot
# bind privileged ports — NEXT-16/TP-09).
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]

# NEXT-16: run as non-root
USER nobody
