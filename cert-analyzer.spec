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
BuildRequires:  git
BuildRequires:  systemd-rpm-macros

Requires:       python3.11
Requires:       systemd

# Tetragon must be installed and running for the analyzer to function
Recommends:     tetragon

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
rm -rf %{_builddir}/proto-venv \
       %{_builddir}/tetragon-src \
       %{_builddir}/generated \
       %{_builddir}/venv

# ── Bootstrap pip (not available as a separate package on UBI9) ──────────────
python3.11 -m ensurepip --upgrade

# ── Generate Tetragon protobuf bindings ───────────────────────────────────────
# Create a temporary venv just for proto generation.
# Use python3.11 explicitly — the venv will have python3.11 but not python3.
python3.11 -m venv %{_builddir}/proto-venv
%{_builddir}/proto-venv/bin/pip install --quiet grpcio-tools==%{_grpcio_version} protobuf==%{_protobuf_version}

mkdir -p %{_builddir}/generated/tetragon

# Fetch Tetragon API protos at the pinned version via sparse git checkout
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/cilium/tetragon.git \
    %{_builddir}/tetragon-src \
    --branch %{_tetragon_version}
cd %{_builddir}/tetragon-src && git sparse-checkout set api/v1/tetragon

%{_builddir}/proto-venv/bin/python3.11 -m grpc_tools.protoc \
    -I %{_builddir}/tetragon-src/api/v1 \
    --python_out=%{_builddir}/generated \
    --grpc_python_out=%{_builddir}/generated \
    %{_builddir}/tetragon-src/api/v1/tetragon/*.proto

touch %{_builddir}/generated/tetragon/__init__.py

# ── Build the bundled virtualenv ──────────────────────────────────────────────
python3.11 -m venv %{_builddir}/venv

%{_builddir}/venv/bin/pip install --quiet --upgrade pip

# Install all runtime dependencies
%{_builddir}/venv/bin/pip install --quiet \
    grpcio==%{_grpcio_version} \
    grpcio-tools==%{_grpcio_version} \
    protobuf==%{_protobuf_version} \
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

# Generated Tetragon protos
cp -r %{_builddir}/generated/tetragon %{buildroot}%{ana_home}/tetragon

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

# ── Licence ───────────────────────────────────────────────────────────────────
install -d %{buildroot}%{_defaultlicensedir}/%{name}
install -m 0644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/LICENSE


%pre
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


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging
