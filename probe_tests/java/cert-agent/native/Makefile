JAVA_HOME ?= $(shell java -XshowSettings:all -version 2>&1 | grep 'java.home' | awk '{print $$3}')
CC        ?= gcc
CFLAGS    := -O2 -fPIC -Wall -Wextra \
             -I$(JAVA_HOME)/include \
             -I$(JAVA_HOME)/include/linux

TARGET    := libcert_agent_stub.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): cert_agent_stub.c
	$(CC) $(CFLAGS) -shared -o $@ $<

clean:
	rm -f $(TARGET)
