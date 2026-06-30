# CertSight — Grafana Dashboard

CertSight ships a pre-built Grafana dashboard at [`extras/examples/grafana-dashboard.json`](examples/grafana-dashboard.json). It requires **Grafana 9.0+** and a **Prometheus** instance scraping the cert-analyzer metrics endpoint.

---

## Quick setup (RHEL 9)

The `install-prometheus.sh` script handles everything in one step: it downloads and starts Prometheus, configures it to scrape cert-analyzer, and imports the dashboard into a running Grafana instance automatically.

```bash
sudo bash extras/install-prometheus.sh
```

If you have changed the Grafana admin password from the default, pass it via environment variable:

```bash
GRAFANA_PASS=yourpassword sudo -E bash extras/install-prometheus.sh
```

On completion the script prints the direct dashboard URL:

```
CertSight dashboard: http://localhost:3000/d/certsight-v1
```

---

## Manual setup

### 1. Install Grafana

```bash
cat <<'EOF' | sudo tee /etc/yum.repos.d/grafana.repo
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF
sudo dnf install -y grafana
sudo systemctl enable --now grafana-server
```

Open `http://localhost:3000` — default login is `admin` / `admin`.

### 2. Allow Grafana to reach Prometheus (SELinux)

On RHEL 9, SELinux blocks Grafana from making outbound network connections by default. Two steps are required — one for the general network boolean and one to label the Prometheus port:

```bash
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 9091
```

If `semanage` is not available, install it first:

```bash
sudo dnf install -y policycoreutils-python-utils
```

### 3. Install Prometheus

The `install-prometheus.sh` script installs Prometheus on port **9091** (to avoid clashing with the cert-analyzer metrics endpoint on 9090):

```bash
sudo bash extras/install-prometheus.sh
```

Or install manually — see the script source for the full binary download and systemd unit.

**Changing the Prometheus port:** If 9091 is already in use, write a systemd drop-in override with your chosen port (e.g. 9092):

```bash
sudo mkdir -p /etc/systemd/system/prometheus.service.d
sudo tee /etc/systemd/system/prometheus.service.d/port.conf > /dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --web.listen-address=:9092
EOF
```

Then reload and restart:

```bash
sudo systemctl daemon-reload && sudo systemctl restart prometheus
```

Update the SELinux label for the new port (`sudo semanage port -a -t http_port_t -p tcp 9092`) and change the datasource URL in Grafana to match.

**Adding a scrape target:** To scrape an additional metrics endpoint, append a new job to `/etc/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: cert-analyzer
    static_configs:
      - targets: ['localhost:9090']

  - job_name: my-service
    static_configs:
      - targets: ['localhost:8080']   # or 'hostname:port' for a remote host
```

Then reload Prometheus to pick it up without a scrape gap:

```bash
sudo systemctl reload prometheus
```

You can verify the target is registered at `http://localhost:9091/targets`.

### 4. Add the Prometheus datasource in Grafana

Connections → Data Sources → Add → Prometheus → set URL to `http://localhost:9091` → Save & Test.

### 5. Import the dashboard

Dashboards → Import → Upload `extras/examples/grafana-dashboard.json` → select the Prometheus datasource → Import.

---

## Dashboard sections

| Section | Panels |
|---|---|
| **Overview** | Analyzer health, total certificates, expired, expiring ≤7/30 days, FIPS non-compliant, self-signed, last event age |
| **Certificate Inventory** | Filterable/sortable table of all certificates with colour-coded expiry; expiry distribution donut; soonest-expiring bar gauge |
| **FIPS Compliance** | Compliant vs non-compliant donut; key algorithm distribution; table of non-compliant certificates with algorithm and hash details |
| **Security** | Self-signed certificate table; Tetragon build/runtime version match; Kafka delivery error rate; self-signed breakdown by namespace |
| **Operational Health** | Event processing rate; analysis error rate by type; cache occupancy time series (vs configured cap); per-cache utilisation % bar gauge |

Template variables at the top of the dashboard filter all panels by **Namespace** and **Node** simultaneously. Both default to "All", which also covers bare-metal deployments where namespace is empty.
