# certsight-fleet-manager.spec
#
# RPM spec for the CertSight fleet manager (extras/fleet-manager/): the
# fleet control console -- node inventory, the nodes x policies matrix,
# per-node and fleet-wide Tetragon policy enable/disable, the fleet
# explorers, and an audit log. See FLEET-MANAGER-README.md.
#
# The server is Python-stdlib only, so unlike certsight-mcp there is no
# bundled virtualenv: it runs on the system python3.11 (RHEL 8's default
# python3 is 3.6, which predates ThreadingHTTPServer). The fleet explorer
# pages are imported straight from the certsight-test-server package's own
# modules (fleet_blast_radius.py etc.) rather than duplicated -- this
# package Requires certsight-test-server and points CERTSIGHT_TEST_SERVER_DIR
# at its install path (see certsight-fleet-manager.service), exactly as
# certsight-mcp does.
#
# SPDX-License-Identifier: Apache-2.0

%global app_home /opt/certsight-fleet-manager
%global app_conf /etc/certsight-fleet-manager

# Dedicated non-privileged service user, same pattern as the other
# certsight-* packages.
%global svc_user  certsight-fleet-manager
%global svc_group certsight-fleet-manager

%define debug_package %{nil}
%global _build_id_links none

Name:           certsight-fleet-manager
Version:        %{_version}
Release:        %{_release}%{?dist}
Summary:        CertSight fleet manager -- Tetragon policy control console
License:        Apache-2.0
URL:            https://github.com/your-org/cert-analyzer
BuildArch:      noarch

# Source tarball created by build-rpm.sh
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  systemd-rpm-macros

Requires:       python3.11
Requires:       systemd
# server.py imports fleet_blast_radius.py/fleet_chain_explorer.py/
# fleet_fips_rollout.py from the test-server package -- see
# certsight-fleet-manager.service's CERTSIGHT_TEST_SERVER_DIR.
Requires:       certsight-test-server


%description
The CertSight fleet control console. Lists every cert-analyzer node
Prometheus is scraping, shows which Tetragon tracing policies are enabled
on which node as a single matrix, and lets an operator switch a policy on
or off on one node or fleet-wide -- durably, because each node's
cert-analyzer records the decision ([control] in cert-analyzer.conf) and
re-applies it after every Tetragon restart. The three fleet explorers
(blast radius, chain explorer, FIPS rollout) are served from the same
console.

There is no unauthenticated mode: a local admin login (scrypt hash in
/etc/certsight-fleet-manager/fleet-manager.conf) gates every page, node
writes carry a shared bearer token, and every login and policy change is
appended to an audit log. The service binds to loopback by default -- put
nginx with TLS in front for anything reachable beyond the host.


%prep
%setup -q


%build
# Nothing to build: pure Python, no compiled or vendored dependencies.


%install
rm -rf %{buildroot}

# ── Application directory ─────────────────────────────────────────────────────
install -d %{buildroot}%{app_home}
install -d %{buildroot}%{app_home}/static
for f in server.py auth.py fleet_state.py node_client.py audit.py; do
    install -m 0644 "$f" %{buildroot}%{app_home}/"$f"
done
for f in index.html app.js app.css; do
    install -m 0644 static/"$f" %{buildroot}%{app_home}/static/"$f"
done
install -m 0644 FLEET-MANAGER-README.md %{buildroot}%{app_home}/FLEET-MANAGER-README.md
install -m 0755 gen-control-certs.sh %{buildroot}%{app_home}/gen-control-certs.sh

# ── Wrapper executable ────────────────────────────────────────────────────────
install -d %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/certsight-fleet-manager << WRAPEOF
#!/bin/sh
exec /usr/bin/python3.11 %{app_home}/server.py "\$@"
WRAPEOF
chmod 0755 %{buildroot}%{_bindir}/certsight-fleet-manager

# ── systemd unit ─────────────────────────────────────────────────────────────
install -d %{buildroot}%{_unitdir}
install -m 0644 certsight-fleet-manager.service %{buildroot}%{_unitdir}/certsight-fleet-manager.service

# ── Configuration ──────────────────────────────────────────────────────────────
# 0640 root:svc_group, not 0644: this file carries the admin password hash
# and the node token.
install -d %{buildroot}%{app_conf}
install -m 0640 fleet-manager.conf %{buildroot}%{app_conf}/fleet-manager.conf

# ── Licence ───────────────────────────────────────────────────────────────────
install -d %{buildroot}%{_defaultlicensedir}/%{name}
install -m 0644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/LICENSE


%pre
getent group %{svc_group} > /dev/null || \
    groupadd --system %{svc_group}
getent passwd %{svc_user} > /dev/null || \
    useradd --system \
            --gid %{svc_group} \
            --home-dir %{app_home} \
            --no-create-home \
            --shell /sbin/nologin \
            --comment "certsight-fleet-manager service account" \
            %{svc_user}
exit 0


%post
%systemd_post certsight-fleet-manager.service
if [ "$1" -eq 1 ]; then
    echo ""
    echo "certsight-fleet-manager installed. Before starting it:"
    echo "  1. Set FLEET_MANAGER_ADMIN_PASSWORD_HASH in %{app_conf}/fleet-manager.conf"
    echo "     (generate with: certsight-fleet-manager --hash-password)"
    echo "  2. Set FLEET_MANAGER_NODE_TOKEN to the nodes' [control] token"
    echo "  3. systemctl enable --now certsight-fleet-manager"
    echo "See %{app_home}/FLEET-MANAGER-README.md"
    echo ""
fi


%preun
%systemd_preun certsight-fleet-manager.service


%postun
%systemd_postun_with_restart certsight-fleet-manager.service


%files
%license %{_defaultlicensedir}/%{name}/LICENSE
%dir %{app_home}
%{app_home}/*.py
%{app_home}/static/
%{app_home}/gen-control-certs.sh
%doc %{app_home}/FLEET-MANAGER-README.md
%{_bindir}/certsight-fleet-manager
%{_unitdir}/certsight-fleet-manager.service
%dir %{app_conf}
%config(noreplace) %attr(0640, root, %{svc_group}) %{app_conf}/fleet-manager.conf


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging of the fleet manager (step 3 of
  extras/FLEET-MANAGER-PLAN.md)
