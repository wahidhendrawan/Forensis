# Production image for Forensis: compilers stay in the build stages, the app runs as a non-root user under gunicorn.
# Rust toolchain for the native PCAP engine (forensis_core); only its wheel reaches the runtime image.
FROM rust:1.99.1-slim-trixie@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247 AS rust

FROM python:3.14-slim@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libyara-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY forensis_core/ /tmp/forensis_core/
# maturin (pinned in forensis_core/pyproject.toml) builds the abi3 wheel with Cargo.lock enforced.
RUN RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH \
    /opt/venv/bin/pip install --no-cache-dir /tmp/forensis_core


FROM python:3.14-slim@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Jakarta
ENV PATH=/opt/venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --no-create-home --home-dir /app forensis

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY . .
# Directories the app writes to at runtime (uploads, SQLite/secret key, Sigma cache, TI cache, entity config).
RUN mkdir -p uploads instance && chown -R forensis:forensis uploads instance sigma_rules threat_intel config

USER forensis
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/v1/health', timeout=4)"

CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "4", "-b", "0.0.0.0:5000", "--timeout", "180", "--no-control-socket", "app:app"]
