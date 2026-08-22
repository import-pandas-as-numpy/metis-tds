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

For credential research, `telemetry.capture_login_passwords` deliberately records parsed SQL-auth passwords in the JSONL sink and requires `telemetry.stdout=false`. `payloads.capture_login_messages` retains every fully framed attacker-supplied TDS 4.2 LOGIN or LOGIN7 message before parsing as a generated mode-`0600` artifact and requires payload capture to be enabled. The older `capture_login7` key remains an alias for existing configurations. Treat both directories as sensitive evidence: restrict access, set retention, and keep them out of container logs and routine log shipping. Generic parser-failure telemetry remains credential-blind.

Set `personality.accept_source_after_attempts` to a positive integer to transition persistent password-spraying sources into the synthetic session after that many parsed SQL-auth attempts. The first `X` attempts follow normal credential policy; later attempts from the same IP are accepted and marked with `source_auth_bypass=true`. Use `null` to disable it. Counters are per-process and reset on restart; integrated authentication remains rejected.

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
        meta skuid "metis-tds" ct state established,related accept
        meta skuid "metis-tds" oifname "lo" accept
        meta skuid "metis-tds" counter drop
    }
}
```

The connection-tracking rule is required so the service can answer inbound clients without gaining permission to initiate a connection. Adjust loopback policy if telemetry is sent to a local collector. The current application itself has no outbound connector, resolver, subprocess, SQL engine, or command-execution backend.

For the container image, use `deploy/nftables-container.conf`. It applies the same policy to the image's numeric runtime UID, `65532`.

## systemd

Install `deploy/metis-tds.service`, review its paths, then run:

```console
sudo systemctl daemon-reload
sudo systemctl enable --now metis-tds
sudo systemctl status metis-tds
```

Keep the configuration and TLS files read-only to the service. Only the log and payload directories should be writable. Do not mount a Docker socket, cloud credentials, package-manager credentials, domain credentials, or production files into the boundary.

## OCI artifact on an isolated VPS

The `Build deployment image` workflow creates a Linux/amd64 OCI archive as a short-lived GitHub Actions artifact. This provides a deployment path for hosts that should not receive repository or registry credentials:

1. Run the workflow against the exact revision to deploy and download `metis-tds.oci.tar` on a trusted workstation.
2. Verify its checksum, copy only the archive and deployment configuration to the VPS, and import it with `podman load --input metis-tds.oci.tar`.
3. Tag the imported image as `localhost/metis-tds:deploy`, then delete the transferred archive from the VPS.
4. Install `deploy/nftables-container.conf` as `/etc/nftables.conf`, `deploy/metis-tds-container.service` as `/etc/systemd/system/metis-tds.service`, and `deploy/metis-tds.logrotate` as `/etc/logrotate.d/metis-tds`. The nftables file owns the host ruleset; merge its table into the existing policy instead if the host already has local firewall rules.
5. Mount the chosen configuration and freshly generated decoy TLS material under `/etc/metis-tds`; neither is baked into the image.

The container unit uses host networking so the host can filter new outbound traffic by UID. It also uses a read-only root filesystem, no capabilities, no-new-privileges, bounded CPU/memory/PIDs, and no container-runtime socket. `--pull=never` guarantees service restarts use the imported image without contacting a registry.

## Internet indexing

Expose TCP/1433 through the inbound firewall/NAT. The first response is a standard TDS packet type `0x04` carrying coherent VERSION, ENCRYPTION, INSTOPT, THREADID, and MARS PRELOGIN options; this is the portion service classifiers generally use to identify MSSQL. Search-engine indexing is external and asynchronous, so verify the resulting service label in the provider after deployment rather than treating local protocol tests as proof of indexing.

Before exposure:

1. Confirm the service runs as the intended UID and cannot read unrelated paths.
2. Confirm an outbound connection attempt under that UID is blocked.
3. Confirm JSONL and payload directories have the intended ownership and retention policy.
4. Run `cargo test --all-targets --locked` and `cargo clippy --all-targets --locked -- -D warnings` on the exact revision.
5. Connect with at least one production client from outside the VM and inspect the complete telemetry timeline.
