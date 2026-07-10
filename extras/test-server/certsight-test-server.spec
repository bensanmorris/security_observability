# certsight-test-server.spec
#
# RPM spec for the CertSight detection test console (extras/test-server/).
# Bundles a Python virtualenv (cryptography + kafka-python) so the package
# is fully self-contained and requires no pip/internet access on the
# target host at install or run time — see TEST-SERVER-README.md.
#
# SPDX-License-Identifier: Apache-2.0

%global app_home /opt/certsight-test-server
%global app_venv %{app_home}/venv
%global app_conf /etc/certsight-test-server

# The service runs as a dedicated non-privileged user, same pattern as
# cert-analyzer.spec
%global svc_user  certsight-test-server
%global svc_group certsight-test-server

# ── Suppress rpmbuild post-processing that breaks bundled venvs ───────────────
# Same rationale as cert-analyzer.spec: do not mangle shebangs inside the
# bundled virtualenv (third-party packages carry '#!/usr/bin/env python'
# scripts rpmbuild otherwise flags as an error), and disable debuginfo /
# build-id symlink generation so the bundled cryptography wheel's
# _rust.abi3.so doesn't collide with system python3.11 RPM files.
%global __brp_mangle_shebangs_exclude_from %{app_home}/.*

%define debug_package %{nil}
%global _build_id_links none
%global __debug_install_post %{nil}
%global __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__os_install_post} \
%{nil}

Name:           certsight-test-server
Version:        %{_version}
Release:        %{_release}%{?dist}
Summary:        Local web console for exercising CertSight's certificate detections
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


%description
A small local HTTP server for manually exercising CertSight's certificate
detections one at a time and watching the resulting Kafka event show up
live. Its built-in use cases generate a fresh self-signed test
certificate and either read it from disk, bind it as a real TLS
listener, or hand it straight to libssl in memory -- exercising
Tetragon's fd_install kprobe, security_socket_bind LSM hook, and
SSL_CTX_use_certificate_ASN1 uprobe respectively -- then stream the
resulting Kafka event to a browser in real time via Server-Sent Events.

This package bundles its own Python virtualenv (cryptography,
kafka-python) so it can be installed and run with no pip/internet access
on the target host. It installs both a standalone `certsight-test-server`
CLI and a certsight-test-server.service systemd unit, enabled on install
so it starts on boot, bound to 0.0.0.0 by default -- see
TEST-SERVER-README.md for the required Kafka broker configuration, use
cases, and how the detection pipeline works end to end.


%prep
%setup -q


%build
# ── Clean any leftover artifacts from a previous build run ───────────────────
rm -rf %{_builddir}/venv

# ── Bootstrap pip (not available as a separate package on UBI9) ──────────────
python3.11 -m ensurepip --upgrade

# ── Build the bundled virtualenv ──────────────────────────────────────────────
python3.11 -m venv %{_builddir}/venv
%{_builddir}/venv/bin/pip install --quiet --upgrade pip
%{_builddir}/venv/bin/pip install \
    cryptography==41.0.7 \
    kafka-python==2.0.3

# Make the venv relocatable by rewriting the build-time prefix to the
# install-time prefix.
sed -i "s|%{_builddir}/venv|%{app_venv}|g" \
    %{_builddir}/venv/bin/activate \
    %{_builddir}/venv/bin/python3.11 \
    %{_builddir}/venv/pyvenv.cfg || true


%install
rm -rf %{buildroot}

# ── Application directory ─────────────────────────────────────────────────────
install -d %{buildroot}%{app_home}
install -d %{buildroot}%{app_venv}
install -d %{buildroot}%{app_home}/static

install -m 0644 server.py             %{buildroot}%{app_home}/server.py
install -m 0644 use_cases.py          %{buildroot}%{app_home}/use_cases.py
install -m 0644 tls_probe_helper.py   %{buildroot}%{app_home}/tls_probe_helper.py
install -m 0644 tcp_connect_probe_helper.py %{buildroot}%{app_home}/tcp_connect_probe_helper.py
install -m 0644 static/index.html     %{buildroot}%{app_home}/static/index.html
install -m 0644 static/app.js         %{buildroot}%{app_home}/static/app.js
install -m 0644 static/app.css        %{buildroot}%{app_home}/static/app.css

# Bundled virtualenv
cp -r %{_builddir}/venv/. %{buildroot}%{app_venv}/

# Rewrite venv paths to their final install location
find %{buildroot}%{app_venv}/bin -type f | xargs grep -rl "%{_builddir}/venv" 2>/dev/null | \
    xargs sed -i "s|%{_builddir}/venv|%{app_venv}|g" || true
sed -i "s|%{_builddir}/venv|%{app_venv}|g" \
    %{buildroot}%{app_venv}/pyvenv.cfg || true

# ── Wrapper executable ────────────────────────────────────────────────────────
# Runs server.py with the bundled venv's interpreter, so callers never need
# to know the venv's path or activate it themselves. Works both run
# interactively from a terminal (--kafka-host/--kafka-port flags) and run
# unattended by the systemd unit below (TEST_SERVER_KAFKA_HOST/
# TEST_SERVER_KAFKA_PORT env vars via EnvironmentFile=) -- see
# server.py's parse_args().
install -d %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/certsight-test-server << WRAPEOF
#!/bin/sh
exec %{app_venv}/bin/python3.11 %{app_home}/server.py "\$@"
WRAPEOF
chmod 0755 %{buildroot}%{_bindir}/certsight-test-server

# ── systemd unit ─────────────────────────────────────────────────────────────
install -d %{buildroot}%{_unitdir}
install -m 0644 certsight-test-server.service %{buildroot}%{_unitdir}/certsight-test-server.service

# ── Configuration ──────────────────────────────────────────────────────────────
install -d %{buildroot}%{app_conf}
install -m 0644 test-server.conf %{buildroot}%{app_conf}/test-server.conf

# ── Licence ───────────────────────────────────────────────────────────────────
install -d %{buildroot}%{_defaultlicensedir}/%{name}
install -m 0644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/LICENSE


%pre
# Create the dedicated service user/group if they don't already exist.
# --no-create-home: the service writes nothing under app_home, only
# /dev/shm (see use_cases.py).
getent group %{svc_group} > /dev/null || \
    groupadd --system %{svc_group}
getent passwd %{svc_user} > /dev/null || \
    useradd --system \
            --gid %{svc_group} \
            --home-dir %{app_home} \
            --no-create-home \
            --shell /sbin/nologin \
            --comment "certsight-test-server service account" \
            %{svc_user}
exit 0


%post
%systemd_post certsight-test-server.service


%preun
%systemd_preun certsight-test-server.service


%postun
%systemd_postun_with_restart certsight-test-server.service


%files
%license %{_defaultlicensedir}/%{name}/LICENSE
%dir %{app_home}
%{app_home}/server.py
%{app_home}/use_cases.py
%{app_home}/tls_probe_helper.py
%{app_home}/tcp_connect_probe_helper.py
%{app_home}/static/
%{app_venv}/
%{_bindir}/certsight-test-server
%{_unitdir}/certsight-test-server.service
%dir %{app_conf}
%config(noreplace) %{app_conf}/test-server.conf


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Add tcp-connect-probe use case (tcp_connect_probe_helper.py) exercising
  CertSight's outbound [port_probe] connect_probe_enabled detection path
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Add in-memory-asn1-cert use case exercising CertSight's
  SSL_CTX_use_certificate_ASN1 uprobe detection path (no new files --
  implemented entirely via ctypes calls into the system libssl within
  use_cases.py)
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Add tls-bind-probe use case (tls_probe_helper.py) exercising CertSight's
  inbound [port_probe] bind_probe_enabled detection path
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Add systemd service (enabled on install, binds 0.0.0.0 by default) and
  environment-variable configuration alongside the existing CLI flags
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging
