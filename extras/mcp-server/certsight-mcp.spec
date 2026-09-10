# certsight-mcp.spec
#
# RPM spec for the CertSight read-only fleet MCP server (extras/mcp-server/).
# Bundles a Python virtualenv (the `mcp` SDK) so the package is fully
# self-contained and requires no pip/internet access on the target host at
# install or run time -- see MCP-SERVER-README.md.
#
# server.py calls straight into the certsight-test-server package's own
# fleet-query modules (blast_radius.py, fleet_blast_radius.py, etc.) rather
# than duplicating them -- this package Requires certsight-test-server and
# points CERTSIGHT_TEST_SERVER_DIR at its install path (see
# certsight-mcp.service) instead of shipping copies that could drift.
#
# SPDX-License-Identifier: Apache-2.0

%global app_home /opt/certsight-mcp
%global app_venv %{app_home}/venv
%global app_conf /etc/certsight-mcp

# The service runs as a dedicated non-privileged user, same pattern as
# cert-analyzer.spec / certsight-test-server.spec
%global svc_user  certsight-mcp
%global svc_group certsight-mcp

# ── Suppress rpmbuild post-processing that breaks bundled venvs ───────────────
# Same rationale as certsight-test-server.spec: do not mangle shebangs inside
# the bundled virtualenv, and disable debuginfo/build-id symlink generation.
%global __brp_mangle_shebangs_exclude_from %{app_home}/.*

%define debug_package %{nil}
%global _build_id_links none
%global __debug_install_post %{nil}
%global __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__os_install_post} \
%{nil}

Name:           certsight-mcp
Version:        %{_version}
Release:        %{_release}%{?dist}
Summary:        Read-only MCP server for querying CertSight fleet data
License:        Apache-2.0
URL:            https://github.com/your-org/cert-analyzer

# Source tarball created by build-rpm.sh
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  python3.11
BuildRequires:  systemd-rpm-macros

Requires:       python3.11
Requires:       systemd
# server.py imports blast_radius.py/fleet_blast_radius.py/chain_explorer.py/
# fleet_fips_rollout.py from the test-server package rather than bundling
# copies -- see certsight-mcp.service's CERTSIGHT_TEST_SERVER_DIR.
Requires:       certsight-test-server


%description
A small read-only MCP (Model Context Protocol) server exposing CertSight's
fleet certificate/FIPS/blast-radius/chain-explorer queries as tools for
Claude Desktop or Claude Code, by calling straight into the same
Prometheus-query functions the test console's own fleet explorer pages use.
Every tool only ever issues a Prometheus read query -- there is no
remote-write path anywhere in this package.

This package bundles its own Python virtualenv (the `mcp` SDK) so it can be
installed and run with no pip/internet access on the target host. It
installs both a standalone `certsight-mcp` CLI and a certsight-mcp.service
systemd unit -- see MCP-SERVER-README.md for the network-transport
configuration and Claude Desktop/Code setup.


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
%{_builddir}/venv/bin/pip install -r requirements.txt

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
install -m 0644 server.py %{buildroot}%{app_home}/server.py

# Bundled virtualenv
cp -r %{_builddir}/venv/. %{buildroot}%{app_venv}/

# Rewrite venv paths to their final install location
find %{buildroot}%{app_venv}/bin -type f | xargs grep -rl "%{_builddir}/venv" 2>/dev/null | \
    xargs sed -i "s|%{_builddir}/venv|%{app_venv}|g" || true
sed -i "s|%{_builddir}/venv|%{app_venv}|g" \
    %{buildroot}%{app_venv}/pyvenv.cfg || true

# ── Wrapper executable ────────────────────────────────────────────────────────
# Runs server.py with the bundled venv's interpreter, so callers never need
# to know the venv's path or activate it themselves.
install -d %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/certsight-mcp << WRAPEOF
#!/bin/sh
exec %{app_venv}/bin/python3.11 %{app_home}/server.py "\$@"
WRAPEOF
chmod 0755 %{buildroot}%{_bindir}/certsight-mcp

# ── systemd unit ─────────────────────────────────────────────────────────────
install -d %{buildroot}%{_unitdir}
install -m 0644 certsight-mcp.service %{buildroot}%{_unitdir}/certsight-mcp.service

# ── Configuration ──────────────────────────────────────────────────────────────
install -d %{buildroot}%{app_conf}
install -m 0644 mcp.conf %{buildroot}%{app_conf}/mcp.conf

# ── Licence ───────────────────────────────────────────────────────────────────
install -d %{buildroot}%{_defaultlicensedir}/%{name}
install -m 0644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/LICENSE


%pre
# Create the dedicated service user/group if they don't already exist.
# --no-create-home: the service writes nothing under app_home.
getent group %{svc_group} > /dev/null || \
    groupadd --system %{svc_group}
getent passwd %{svc_user} > /dev/null || \
    useradd --system \
            --gid %{svc_group} \
            --home-dir %{app_home} \
            --no-create-home \
            --shell /sbin/nologin \
            --comment "certsight-mcp service account" \
            %{svc_user}
exit 0


%post
%systemd_post certsight-mcp.service


%preun
%systemd_preun certsight-mcp.service


%postun
%systemd_postun_with_restart certsight-mcp.service


%files
%license %{_defaultlicensedir}/%{name}/LICENSE
%dir %{app_home}
%{app_home}/server.py
%{app_venv}/
%{_bindir}/certsight-mcp
%{_unitdir}/certsight-mcp.service
%dir %{app_conf}
%config(noreplace) %{app_conf}/mcp.conf


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging -- previously only run straight out of a git
  checkout with a hand-built venv (see MCP-SERVER-README.md and
  extras/aws-demo/user-data.sh)
