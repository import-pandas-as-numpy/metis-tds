FROM rust:1.97-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Metis TDS" \
    org.opencontainers.image.description="Contained, stateful Microsoft SQL Server TDS honeypot" \
    org.opencontainers.image.source="https://github.com/import-pandas-as-numpy/metis-tds" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.revision="${VCS_REF}"
RUN groupadd --system --gid 65532 metis-tds \
    && useradd --system --uid 65532 --gid 65532 --home-dir /var/lib/metis-tds --shell /usr/sbin/nologin metis-tds \
    && install -d -o metis-tds -g metis-tds -m 0700 /var/lib/metis-tds/payloads /var/log/metis-tds \
    && install -d -o root -g root -m 0755 /usr/share/licenses/metis-tds
COPY --from=builder /build/target/release/metis-tds /usr/local/bin/metis-tds
COPY LICENSE /usr/share/licenses/metis-tds/LICENSE
USER 65532:65532
EXPOSE 1433/tcp
ENTRYPOINT ["/usr/local/bin/metis-tds"]
CMD ["--config", "/etc/metis-tds/config.json"]
