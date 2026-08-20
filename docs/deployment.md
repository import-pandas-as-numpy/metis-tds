# Secure deployment

Metis is designed to receive hostile traffic. A memory-safe parser is not a substitute for host isolation. Deploy it in a dedicated VM or equivalent strong boundary, under a unique unprivileged identity, with no production secrets and outbound network access denied.

## Build and install

```console
cargo build --release --locked
sudo install -o root -g root -m 0755 target/release/metis-tds /usr/local/bin/metis-tds
sudo useradd --system --home-dir /var/lib/metis-tds --shell /usr/sbin/nologin metis-tds
sudo install -d -o root -g metis-tds -m 0750 /etc/metis-tds
sudo install -d -o metis-tds -g metis-tds -m 0750 /var/lib/metis-tds/payloads /var/log/metis-tds
sudo install -o root -g metis-tds -m 0640 config/example.json /etc/metis-tds/config.json
```

Set `listener.address` to `0.0.0.0:1433`, move telemetry and payload paths under the directories above, and configure a decoy personality. Never use a real username/password pair or an identity that exists elsewhere.

## TLS

TLS modes are:

- `disabled`: advertise that encryption is unsupported. Useful only for isolated compatibility testing.
- `optional`: honor clients that request encryption; allow plaintext clients.
- `preferred`: advertise encryption when the client supports it.
- `required`: require TDS 7.x PRELOGIN-wrapped TLS and reject clients that advertise no TLS support.

The runtime accepts an X.509 certificate in DER form and an unencrypted PKCS#8 private key in DER form. Certificate paths come only from trusted configuration.

```console
openssl x509 -in server.crt -outform DER -out server-cert.der
openssl pkcs8 -topk8 -inform PEM -outform DER -in server.key -nocrypt -out server-key.der
sudo install -o root -g metis-tds -m 0640 server-cert.der server-key.der /etc/metis-tds/
```

Use a certificate issued for the exposed DNS name. Set `tls.mode` to `required`, `tls.certificate_der` to `/etc/metis-tds/server-cert.der`, and `tls.private_key_der` to `/etc/metis-tds/server-key.der`.

## Outbound deny

Enforce outbound denial outside the process. For example, with nftables and a dedicated service UID:

```nft
table inet metis_honeypot {
    chain output {
        type filter hook output priority 0; policy accept;
        meta skuid "metis-tds" oifname "lo" accept
        meta skuid "metis-tds" counter drop
    }
}
```

Adjust loopback policy if telemetry is sent to a local collector. The current application itself has no outbound connector, resolver, subprocess, SQL engine, or command-execution backend.

## systemd

Install `deploy/metis-tds.service`, review its paths, then run:

```console
sudo systemctl daemon-reload
sudo systemctl enable --now metis-tds
sudo systemctl status metis-tds
```

Keep the configuration and TLS files read-only to the service. Only the log and payload directories should be writable. Do not mount a Docker socket, cloud credentials, package-manager credentials, domain credentials, or production files into the boundary.

## Internet indexing

Expose TCP/1433 through the inbound firewall/NAT. The first response is a standard TDS packet type `0x04` carrying coherent VERSION, ENCRYPTION, INSTOPT, THREADID, and MARS PRELOGIN options; this is the portion service classifiers generally use to identify MSSQL. Search-engine indexing is external and asynchronous, so verify the resulting service label in the provider after deployment rather than treating local protocol tests as proof of indexing.

Before exposure:

1. Confirm the service runs as the intended UID and cannot read unrelated paths.
2. Confirm an outbound connection attempt under that UID is blocked.
3. Confirm JSONL and payload directories have the intended ownership and retention policy.
4. Run `cargo test --all-targets --locked` and `cargo clippy --all-targets --locked -- -D warnings` on the exact revision.
5. Connect with at least one production client from outside the VM and inspect the complete telemetry timeline.
