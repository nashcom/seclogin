CC      = gcc

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

CFLAGS  = -O2                       \
          -Wall -Wextra              \
          -fstack-protector-strong   \
          -D_FORTIFY_SOURCE=2        \
          -fPIE                      \
          -ffunction-sections        \
          -fdata-sections            \
          -fvisibility=hidden         \
          -DSECLOGIN_VERSION=\"$(VERSION)\"

LDFLAGS = -pie                       \
          -Wl,-z,relro,-z,now        \
          -Wl,--gc-sections          \
          -lcrypto

# For static Alpine build: see Makefile.alpine
# Algorithm (SHA256/SHA1) is set in /etc/seclogin.conf — no recompile needed

BIN          = seclogin
BIN_GATE     = seclogin-gate

PREFIX       = /usr/local/bin

# seclogin: SUID root, seclogin group executes
GROUP        = seclogin
MODE         = 4750

# seclogin-gate: SUID+SGID seclogin — sets both euid and egid to seclogin
# SGID required so egid=seclogin for group-readable config/secrets
# TODO: replace world-execute with a dedicated group for production
GATE_USER    = seclogin
GATE_GROUP   = seclogin
MODE_GATE    = 6755

.PHONY: all install install-gate clean

all: $(BIN)

$(BIN): seclogin.c
	$(CC) $(CFLAGS) seclogin.c -o $(BIN) $(LDFLAGS)

install: $(BIN)
	@echo "Installing $(BIN) → $(PREFIX)/$(BIN)  (root:$(GROUP) $(MODE))"
	install -o root -g $(GROUP) -m $(MODE) $(BIN) $(PREFIX)/$(BIN)
	ls -lh $(PREFIX)/$(BIN)

install-gate: $(BIN)
	@echo "Installing $(BIN_GATE) → $(PREFIX)/$(BIN_GATE)  ($(GATE_USER):$(GATE_GROUP) $(MODE_GATE))"
	@if ! getent passwd $(GATE_USER) > /dev/null 2>&1; then \
	    echo "ERROR: user '$(GATE_USER)' not found."; \
	    echo "       Run: sudo ./create_seclogin_user.sh"; \
	    exit 1; \
	fi
	install -o $(GATE_USER) -g $(GATE_GROUP) -m $(MODE_GATE) $(BIN) $(PREFIX)/$(BIN_GATE)
	ls -lh $(PREFIX)/$(BIN_GATE)

clean:
	rm -f $(BIN)
