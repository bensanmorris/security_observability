# CertSight Quickstart

Prerequisites: RHEL8 or RHEL9, root access, internet access for downloads.

---

## 1. Install Tetragon

```bash
# Download and install the Tetragon binary
curl -LO https://github.com/cilium/tetragon/releases/download/v1.1.0/tetragon-v1.1.0-amd64.tar.gz
tar -xzf tetragon-v1.1.0-amd64.tar.gz
sudo install -m 0755 tetragon/tetragon /usr/local/bin/tetragon
sudo install -m 0755 tetragon/tetra    /usr/local/bin/tetra

# Create the systemd service
sudo tee /etc/systemd/system/tetragon.service > /dev/null << 'EOF'
[Unit]
Description=Tetragon eBPF Security Observability
After=network.target

[Service]
ExecStart=/usr/local/bin/tetragon
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now tetragon
sudo systemctl status tetragon
```

---

## 2. Load the Tetragon certificate policy

Download the policies archive from the [latest GitHub Release](https://github.com/bensanmorris/security_observability/releases/latest):

```bash
# Extract the policies archive (downloaded from the GitHub Release page)
tar -xzf tetragon-policies-<version>.tar.gz

# Load the certificate file access policy
sudo tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml

# Verify it loaded
sudo tetra tracingpolicy list
```

---

## 3. Install the cert-analyzer RPM

```bash
# Download the RPM from the GitHub Release page, then:

# Verify Tetragon is in PATH (required by the RPM pre-install check)
command -v tetragon

# Install
sudo dnf install ./cert-analyzer-<version>.el9.x86_64.rpm
```

---

## 4. Fix the Tetragon socket permissions

```bash
# Grant cert-analyzer access to the Tetragon gRPC socket
sudo chgrp cert-analyzer /run/tetragon/tetragon.sock

# Make it permanent across Tetragon restarts
sudo systemctl edit tetragon
```

Add the following, save and exit:

```ini
[Service]
ExecStartPost=/bin/chgrp cert-analyzer /run/tetragon/tetragon.sock
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart tetragon
```

---

## 5. Configure and start cert-analyzer

```bash
sudo vi /etc/cert-analyzer/cert-analyzer.conf
```

Set the Tetragon socket address:

```ini
[tetragon]
addr = unix:///run/tetragon/tetragon.sock
```

```bash
sudo systemctl enable --now cert-analyzer
sudo systemctl status cert-analyzer
```

---

## 6. Verify

```bash
# Watch live detections
sudo journalctl -u cert-analyzer -f

# Trigger a detection (in another terminal)
cat /etc/pki/tls/certs/ca-bundle.crt

# Check Prometheus metrics
curl -s http://localhost:9090/metrics | grep tls_certificate_expiry_days

# Check health probes
curl -s http://localhost:8086/healthz
curl -s http://localhost:8086/readyz
```

You should see `🔍 Detected certificate access` in the logs within a second of the `cat` command.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `tetragon binary not found in PATH` | Install Tetragon first (step 1) |
| `Tetragon connection lost (UNAVAILABLE)` | Check socket path in config and socket group permissions (step 4) |
| `Tetragon version check incomplete — build: unknown` | Run `sudo systemctl daemon-reload && sudo systemctl restart cert-analyzer` |
| Detection seen but no expiry logged | Cert already in cache — restart the analyzer to clear it |
| `Certificate file not found` | Set `host_prefix =` (empty) in `[certificates]` for standalone mode |
