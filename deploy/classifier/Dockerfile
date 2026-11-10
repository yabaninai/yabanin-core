# Multi-stage build for ML classifier service
# python:3.12-slim digest-pinned 2026-10-25 via `docker buildx imagetools inspect`
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS base

# R002-D1: shipped Python deps pinned via the committed constraints file.
COPY deploy/python-constraints.txt /tmp/python-constraints.txt
RUN pip install --no-cache-dir -c /tmp/python-constraints.txt torch transformers uvicorn fastapi sentencepiece numpy accelerate

FROM base AS serve

COPY deploy/classifier/server.py /app/server.py
COPY deploy/classifier/generate_fallback.py /app/generate_fallback.py

# R077 D-1 (owner decision 2026-10-16): optional trained-checkpoint COPY.
# artifacts/classifier-v1.pt is a gitignored build artifact; from a clean
# checkout not even artifacts/ exists, so EVERY may-be-absent path segment
# carries a wildcard (a bare prefix would lstat-fail) and
# deploy/classifier/generate_fallback.py is the always-present anchor that
# keeps this COPY valid when the glob matches nothing. Clean-context builds
# proceed without the trained checkpoint (fallback branch below).
COPY deploy/classifier/generate_fallback.py artifacts*/classifier-v1.pt* /checkpoint/

RUN if [ -s /checkpoint/classifier-v1.pt ]; then \
        mv /checkpoint/classifier-v1.pt /app/model.pt && \
        echo "trained:classifier-v1.pt" > /app/MODEL_SOURCE && \
        echo "classifier: trained checkpoint classifier-v1.pt provided at build time"; \
    else \
        python /app/generate_fallback.py && \
        echo "fallback:random-head" > /app/MODEL_SOURCE && \
        echo "classifier: trained checkpoint classifier-v1.pt NOT in build context - generated fallback model"; \
    fi && rm -rf /checkpoint

WORKDIR /app

EXPOSE 8080

# Model provenance is logged at startup so an image without the trained
# checkpoint never masquerades as a trained one; exec keeps uvicorn PID 1.
CMD ["sh", "-c", "echo \"classifier: model source: $(cat /app/MODEL_SOURCE 2>/dev/null || echo unknown)\" && exec uvicorn server:app --host 0.0.0.0 --port 8080"]

# NEXT-16: run as non-root
# nobody's HOME (/nonexistent) is unwritable, which made the startup HF hub
# cache lookup crash before /health could ever answer; use a writable cache.
ENV HF_HOME=/tmp/hf-cache
USER nobody
