# cert-agent-jni.spec
#
# RPM spec for the cert-agent Java instrumentation agent and JNI native stub.
#
# The fat JAR (cert-agent.jar) is pre-built and included in the source tarball
# — it is pure Java bytecode and not architecture-specific.  The native stub
# (libcert_agent_stub.so) is compiled during %%build because it links against
# JNI headers and must target the correct JDK ABI.
#
# To target a different JDK's devel headers at build time, rebuild with:
#   rpmbuild --define '_java_version 17' ...
# Note this only affects which JDK's <jni.h> the native stub compiles
# against -- JNI ABI is stable across JDK versions, so the resulting
# cert-agent.jar/libcert_agent_stub.so built here are validated to run
# unmodified against both Java 11 and Java 17 *target* JVMs (the JVM
# the agent gets attached to). No per-version subpackages needed unless
# that assumption is ever disproven.
#
# SPDX-License-Identifier: Apache-2.0

%{!?_java_version: %global _java_version 11}

# Derive the JDK package name and home directory from _java_version.
# On RHEL9 javac is at /usr/bin/javac -> /etc/alternatives/javac ->
# /usr/lib/jvm/java-<ver>-openjdk-<ver>.el9.x86_64/bin/javac.
# readlink -f resolves the whole chain reliably.
%global jdk_pkg    java-%{_java_version}-openjdk-devel
%global install_dir /opt/cert-agent

%define debug_package %{nil}
%global _build_id_links none

Name:     cert-agent-jni
Version:  %{_version}
Release:  %{_release}%{?dist}
Summary:  Java agent and JNI native stub for TLS certificate interception
License:  Apache-2.0
URL:      https://github.com/your-org/cert-analyzer

Source0:  %{name}-%{version}.tar.gz

# The devel package is needed for <jni.h> to compile the native stub.
BuildRequires: %{jdk_pkg}
BuildRequires: gcc

%description
Java instrumentation agent and JNI native stub library used by cert-analyzer
to intercept TLS certificate operations inside running JVM processes.

The agent can be injected dynamically via the JVM Attach API (using jattach,
provided by cert-agent-deployer) or statically via the -javaagent JVM flag.


%prep
%setup -q


%build
# Resolve JAVA_HOME from wherever javac actually lives after alternatives
# resolution — this works regardless of JDK minor version or install path.
JAVA_HOME=$(readlink -f /usr/bin/javac | sed 's|/bin/javac||')
export JAVA_HOME

make -C native JAVA_HOME="$JAVA_HOME"


%install
rm -rf %{buildroot}

install -d %{buildroot}%{install_dir}

# Pre-built fat JAR (bundled in source tarball; built offline from Java sources
# + bundled ASM bytecode manipulation library).
install -m 0644 cert-agent.jar %{buildroot}%{install_dir}/cert-agent.jar

# Native stub, compiled above against the target JDK's JNI headers.
install -m 0755 native/libcert_agent_stub.so \
    %{buildroot}%{install_dir}/libcert_agent_stub.so


%files
%license LICENSE

%dir %{install_dir}
%attr(0644, root, root) %{install_dir}/cert-agent.jar
%attr(0755, root, root) %{install_dir}/libcert_agent_stub.so


%changelog
* %(date "+%a %b %d %Y") Build System <build@your-org.internal> - %{version}-%{release}
- Initial RPM packaging
