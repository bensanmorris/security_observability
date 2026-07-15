JAVA_HOME ?= $(shell java -XshowSettings:all -version 2>&1 | grep 'java.home' | awk '{print $$3}')
CC        ?= gcc
# ?= (not :=) so a caller -- notably cert-agent-jni.spec's %build, which
# exports RPM's full hardened %{optflags}/%{build_ldflags} -- can override
# these without being silently clobbered. Bare defaults here still apply
# baseline hardening (stack protector, FORTIFY_SOURCE, full RELRO) for
# standalone/dev builds run outside the RPM.
CFLAGS    ?= -O2 -fPIC -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS   ?= -Wl,-z,relro,-z,now
INCLUDES  := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

TARGET    := libcert_agent_stub.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): cert_agent_stub.c
	$(CC) $(CFLAGS) $(INCLUDES) -shared -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
