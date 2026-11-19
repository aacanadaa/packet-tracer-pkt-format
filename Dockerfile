FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/aacanadaa/packet-tracer-pkt-format"
LABEL org.opencontainers.image.description="Read, write, and generate Cisco Packet Tracer .pkt/.pka files offline"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && rm -rf /app \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin pkt \
    && mkdir -p /work \
    && chown pkt:pkt /work

USER pkt
WORKDIR /work
ENTRYPOINT ["pkt"]
CMD ["--help"]
