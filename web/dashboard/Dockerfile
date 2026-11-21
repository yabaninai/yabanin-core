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
COPY design /src/design
COPY scripts/web/bundle_budget.mjs ../../scripts/web/bundle_budget.mjs
RUN npm run build
COPY LICENSE NOTICE LICENSING.md /src/
COPY scripts/release/dashboard-notices.mjs /src/scripts/release/
RUN ./node_modules/.bin/vite build --sourcemap --manifest --outDir /tmp/dashboard-maps \
    && node /src/scripts/release/dashboard-notices.mjs --map-root /tmp/dashboard-maps --out dist/licenses

# Serve stage
# nginx:alpine digest-pinned 2026-10-25 via `docker buildx imagetools inspect` (relprep §9 follow-up)
FROM nginx:alpine@sha256:713fc2ebfd92e8217db451477182ee91944b123d2b1ee9fd5a8c6e91ca6c3a11
COPY --from=builder /src/web/dashboard/dist /usr/share/nginx/html
COPY web/dashboard/nginx-main.conf /etc/nginx/nginx.conf
COPY web/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
# COPY preserves build-context modes, so a checkout with 0600 files / 0700
# dirs would ship unreadable content to the unprivileged runtime user.
# Normalize delivered content: 0644 for regular files (static assets,
# license notices, nginx configs), 0755 for directories (NEXT-16/TP-09).
RUN find /usr/share/nginx/html -type d -exec chmod 0755 {} + \
    && find /usr/share/nginx/html -type f -exec chmod 0644 {} + \
    && chmod 0755 /etc/nginx /etc/nginx/conf.d \
    && chmod 0644 /etc/nginx/nginx.conf /etc/nginx/conf.d/default.conf
# nginx creates only the last path component itself; pre-create the /tmp
# temp trees writable by the unprivileged runtime user (nobody:nogroup).
RUN mkdir -p /tmp/nginx/client /tmp/nginx/proxy /tmp/nginx/fastcgi     /tmp/nginx/uwsgi /tmp/nginx/scgi     && chown -R nobody:nogroup /tmp/nginx
# Unprivileged listener (nginx.conf listens on 8080; USER nobody cannot
# bind privileged ports — NEXT-16/TP-09).
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]

# NEXT-16: run as non-root
USER nobody
