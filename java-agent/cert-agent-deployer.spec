# cert-agent-deployer.spec
#
# RPM spec for the cert-agent deployer daemon.
#
# Watches /proc for new JVM processes and injects cert-agent.jar via jattach.
# Intentionally version-decoupled from cert-agent-jni: the deployer only needs
# the JAR and .so to exist at the expected paths — it has no version-specific
# logic and can work against any cert-agent-jni release.
#
# Bundles jattach (https://github.com/jattach/jattach) as a pre-built binary
# included in the source tarball.  jattach is a zero-dependency static binary
# so no additional Requires are needed for it.
#
# SPDX-License-Identifier: Apache-2.0

%define debug_package %{nil}

Name:     cert-agent-deployer
Version:  %{_version}
Release:  %{_release}%{?dist}
Summary:  Daemon that dynamically attaches cert-agent to running JVMs
License:  Apache-2.0
URL:      https://github.com/your-org/cert-analyzer

Source0:  %{name}-%{version}.tar.gz

BuildRequires: systemd-rpm-macros
BuildRequires: checkpolicy
BuildRequires: policycoreutils

# python3 is used to run the deployer script; stdlib only, no venv needed.
Requires: python3
# cert-agent-jni provides the JAR and .so this service injects.
# No version pin — the deployer is designed to work across JNI releases.
Requires: cert-agent-jni

%global deploy_dir /opt/cert-agent-deployer

%description
Scans /proc for JVM processes and attaches cert-agent.jar via jattach.
On successful attach the JVM begins reporting TLS certificate operations
to cert-analyzer via the Tetragon uprobe.

When dynamic attach is rejected (e.g. the JVM requires
-XX:+EnableDynamicAgentLoading), the deployer logs the equivalent
-javaagent flag needed for static injection on the next JVM restart.

Requires cert-agent-jni to be installed for the JAR and native stub.


%global selinux_pp %{deploy_dir}/cert-agent-deployer.pp

%prep
%setup -q


%build
checkmodule -M -m -o cert-agent-deployer.mod cert-agent-deployer.te
semodule_package -o cert-agent-deployer.pp -m cert-agent-deployer.mod


%install
rm -rf %{buildroot}

install -d %{buildroot}%{deploy_dir}
install -d %{buildroot}%{_unitdir}

install -m 0755 java_agent_deployer.py \
    %{buildroot}%{deploy_dir}/java_agent_deployer.py

# jattach — pre-built upstream static binary, included in the source tarball.
install -m 0755 jattach %{buildroot}%{deploy_dir}/jattach

install -m 0644 cert-agent-deployer.service \
    %{buildroot}%{_unitdir}/cert-agent-deployer.service

install -m 0644 cert-agent-deployer.pp \
    %{buildroot}%{selinux_pp}


%post
%systemd_post cert-agent-deployer.service
semodule -i %{selinux_pp} 2>/dev/null || true


%preun
%systemd_preun cert-agent-deployer.service
if [ $1 -eq 0 ]; then
    semodule -r cert_agent_deployer 2>/dev/null || true
fi


%postun
%systemd_postun_with_restart cert-agent-deployer.service


%files
%license LICENSE

%dir %{deploy_dir}
%attr(0755, root, root) %{deploy_dir}/java_agent_deployer.py
%attr(0755, root, root) %{deploy_dir}/jattach
%attr(0644, root, root) %{selinux_pp}

%{_unitdir}/cert-agent-deployer.service


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging
