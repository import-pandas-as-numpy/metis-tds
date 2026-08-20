FROM rust:1.96-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN groupadd --system --gid 65532 metis-tds \
    && useradd --system --uid 65532 --gid 65532 --home-dir /var/lib/metis-tds --shell /usr/sbin/nologin metis-tds \
    && install -d -o metis-tds -g metis-tds -m 0700 /var/lib/metis-tds/payloads /var/log/metis-tds
COPY --from=builder /build/target/release/metis-tds /usr/local/bin/metis-tds
USER 65532:65532
EXPOSE 1433/tcp
ENTRYPOINT ["/usr/local/bin/metis-tds"]
CMD ["--config", "/etc/metis-tds/config.json"]
