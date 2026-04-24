# cert-analyzer.spec
#
# RPM spec for the TLS Certificate Expiry Monitor.
# Bundles a Python virtualenv so the package is fully self-contained
# and requires no internet access at install time.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Your Organisation

# ── Suppress rpmbuild post-processing that breaks bundled venvs ───────────────

# Do not mangle shebangs inside the bundled virtualenv — third-party packages
# (e.g. protobuf) contain scripts with '#!/usr/bin/env python' which rpmbuild
# treats as an error. The venv interpreter is already correctly set.
# Also exclude cert_analyzer.py — it uses '#!/usr/bin/env python3' intentionally
# so it resolves to the venv python at runtime via ExecStart in the service file.
%global __brp_mangle_shebangs_exclude_from /opt/cert-analyzer/.*

# Completely disable debuginfo processing and build-id symlink generation.
# Bundled wheels (specifically cryptography's _rust.abi3.so) share build IDs
# with system python3.11 RPM files, causing install-time conflicts if build-id
# symlinks are generated.
%define debug_package %{nil}
%global _build_id_links none
%global __debug_install_post %{nil}

# Override __spec_install_post to remove find-debuginfo entirely.
# This is the only reliable way to prevent build-id symlink generation on
# RHEL9 / RPM 4.17+ when bundling third-party compiled extensions.
%global __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__os_install_post} \
%{nil}

Name:           cert-analyzer
Version:        %{_version}
Release:        %{_release}%{?dist}
Summary:        TLS Certificate Expiry Monitor using Tetragon eBPF hooks
License:        Apache-2.0
URL:            https://github.com/your-org/cert-analyzer

# Source tarball created by build-rpm.sh
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  python3.11
BuildRequires:  python3.11-devel
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros

Requires:       python3.11
Requires:       systemd

# Tetragon is a runtime dependency but is installed manually rather than via
# an RPM repository. Its installation path varies by environment so we cannot
# use a file-based Requires. Instead the %pre scriptlet checks for the
# tetragon binary in $PATH and fails the install with a clear message if absent.

# The analyzer runs as a dedicated non-privileged user
%global ana_user  cert-analyzer
%global ana_group cert-analyzer
%global ana_home  /opt/cert-analyzer
%global ana_venv  /opt/cert-analyzer/venv
%global ana_conf  /etc/cert-analyzer
%global ana_log   /var/log/cert-analyzer


%description
cert-analyzer monitors TLS certificate expiry by hooking Tetragon eBPF
fd_install kprobe events. When a process opens a certificate file the
analyzer parses it, extracts expiry metadata, and publishes Prometheus
metrics. Supports PEM, DER, JKS, and PKCS12 formats with Kubernetes
workload enrichment.


%prep
%setup -q


%build
# ── Clean any leftover artifacts from a previous build run ───────────────────
rm -rf %{_builddir}/venv

# ── Bootstrap pip (not available as a separate package on UBI9) ──────────────
python3.11 -m ensurepip --upgrade

# ── Build the bundled virtualenv ──────────────────────────────────────────────
# Tetragon protobuf bindings are pre-generated and included in the source
# tarball under tetragon/ — the spec does not clone or fetch external repos.
python3.11 -m venv %{_builddir}/venv

%{_builddir}/venv/bin/pip install --quiet --upgrade pip

# Install all runtime dependencies
%{_builddir}/venv/bin/pip install --quiet \
    grpcio==1.60.1 \
    grpcio-tools==1.60.1 \
    protobuf==4.25.3 \
    prometheus-client==0.19.0 \
    cryptography==41.0.7 \
    pyyaml==6.0.1 \
    kubernetes>=28.1.0 \
    pyjks==20.0.0

# Make the venv relocatable by rewriting the shebang paths.
# We do this by replacing the absolute build-time prefix with the
# install-time prefix using virtualenv's --relocatable flag (if available)
# or by sed on the activate script.
sed -i "s|%{_builddir}/venv|%{ana_venv}|g" \
    %{_builddir}/venv/bin/activate \
    %{_builddir}/venv/bin/python3.11 \
    %{_builddir}/venv/pyvenv.cfg || true


%install
rm -rf %{buildroot}

# ── Application directory ─────────────────────────────────────────────────────
install -d %{buildroot}%{ana_home}
install -d %{buildroot}%{ana_venv}
install -d %{buildroot}%{ana_conf}
install -d %{buildroot}%{ana_log}

# Main analyzer script
install -m 0755 cert_analyzer.py %{buildroot}%{ana_home}/cert_analyzer.py

# Generated Tetragon protos — pre-built and included in the source tarball
cp -r tetragon %{buildroot}%{ana_home}/tetragon

# Bundled virtualenv
cp -r %{_builddir}/venv/. %{buildroot}%{ana_venv}/

# Rewrite venv paths to final install location
find %{buildroot}%{ana_venv}/bin -type f | xargs grep -rl "%{_builddir}/venv" 2>/dev/null | \
    xargs sed -i "s|%{_builddir}/venv|%{ana_venv}|g" || true
sed -i "s|%{_builddir}/venv|%{ana_venv}|g" \
    %{buildroot}%{ana_venv}/pyvenv.cfg || true

# ── Configuration ─────────────────────────────────────────────────────────────
# Install default config — marked %%config(noreplace) so upgrades
# don't overwrite operator customisations
install -m 0640 cert-analyzer.conf %{buildroot}%{ana_conf}/cert-analyzer.conf

# ── systemd unit ─────────────────────────────────────────────────────────────
install -d %{buildroot}%{_unitdir}
install -m 0644 cert-analyzer.service %{buildroot}%{_unitdir}/cert-analyzer.service

# Stamp build-time version constants into the unit as Environment directives.
# These are not operator-configurable — they reflect exactly what was built
# and are used by the analyzer's version check and Prometheus build_info metric.
# Using a systemd drop-in keeps the base unit file clean and version-independent.
install -d %{buildroot}%{_unitdir}/cert-analyzer.service.d
cat > %{buildroot}%{_unitdir}/cert-analyzer.service.d/version.conf << 'UNITEOF'
[Service]
Environment=TETRAGON_BUILD_VERSION=%{_tetragon_version}
Environment=CERT_ANALYZER_VERSION=%{_version}
UNITEOF

# ── Licence ───────────────────────────────────────────────────────────────────
install -d %{buildroot}%{_defaultlicensedir}/%{name}
install -m 0644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/LICENSE


%pre
# Verify Tetragon is installed — it is a required runtime dependency but is
# not available as an RPM so cannot be expressed as a package Requires.
# RPM scriptlets run with a restricted PATH (/bin:/usr/bin:/sbin:/usr/sbin)
# so we search common installation locations explicitly rather than relying
# on command -v which would miss /usr/local/bin in the scriptlet environment.
TETRAGON_FOUND=0
for dir in /usr/local/bin /usr/bin /bin /sbin /usr/sbin /opt/tetragon/bin; do
    if [ -x "${dir}/tetragon" ]; then
        TETRAGON_FOUND=1
        break
    fi
done
if [ "${TETRAGON_FOUND}" -eq 0 ]; then
    echo "ERROR: tetragon binary not found." >&2
    echo "       Install Tetragon before installing cert-analyzer." >&2
    echo "       See https://tetragon.io/docs/installation/" >&2
    exit 1
fi

# Create service user and group if they don't exist
getent group %{ana_group} > /dev/null || \
    groupadd --system %{ana_group}
getent passwd %{ana_user} > /dev/null || \
    useradd --system \
            --gid %{ana_group} \
            --home-dir %{ana_home} \
            --no-create-home \
            --shell /sbin/nologin \
            --comment "cert-analyzer service account" \
            %{ana_user}
exit 0


%post
%systemd_post cert-analyzer.service

# Fix ownership of installed files
chown -R %{ana_user}:%{ana_group} %{ana_home}
chown -R %{ana_user}:%{ana_group} %{ana_log}
chown    root:%{ana_group}         %{ana_conf}/cert-analyzer.conf
chmod    0640                      %{ana_conf}/cert-analyzer.conf

echo "cert-analyzer installed."
echo "Edit /etc/cert-analyzer/cert-analyzer.conf then run:"
echo "  systemctl enable --now cert-analyzer"


%preun
%systemd_preun cert-analyzer.service


%postun
%systemd_postun_with_restart cert-analyzer.service


%files
%license %{_defaultlicensedir}/%{name}/LICENSE

# Application
%dir %{ana_home}
%attr(0755, %{ana_user}, %{ana_group}) %{ana_home}/cert_analyzer.py
%{ana_home}/tetragon/
%{ana_venv}/

# Configuration — noreplace preserves operator edits on upgrade
%dir %{ana_conf}
%config(noreplace) %attr(0640, root, %{ana_group}) %{ana_conf}/cert-analyzer.conf

# Log directory
%dir %attr(0750, %{ana_user}, %{ana_group}) %{ana_log}

# systemd
%{_unitdir}/cert-analyzer.service
%{_unitdir}/cert-analyzer.service.d/version.conf


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging
