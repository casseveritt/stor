# Stage 1: build — compile C extensions against sqlcipher headers
FROM python:3.13-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /build/
RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir -r /build/requirements.txt

# Stage 2: runtime — only the shared library, no build tools
FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

WORKDIR /app
COPY . .

# /data is mounted at runtime (server store or client config dir)
VOLUME ["/data"]
