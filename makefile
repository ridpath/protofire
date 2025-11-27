# protofire - Modular OT/ICS Protocol Fuzzer
# ==========================================

CC      := gcc
CFLAGS  := -Wall -Wextra -Wno-unused-parameter -std=c99 \
           -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE \
           -O2 -g -I.
LDFLAGS := -lpthread -lpcap -ldl -lm
VERSION := 0.1.0

BIN     := protofire

OBJS := fuzzer.o fuzzer_protocol_common.o

# Protocol modules
MODBUS_OBJ := plugins/modbus_module.o
DNP3_OBJ   := plugins/dnp3_module.o
S7COMM_OBJ := plugins/s7comm_module.o
IEC104_OBJ := plugins/iec104_module.o
OPCUA_OBJ  := plugins/opc_ua_module.o

PROTOCOL_OBJS := $(MODBUS_OBJ) $(DNP3_OBJ) $(S7COMM_OBJ) $(IEC104_OBJ) $(OPCUA_OBJ)
PROTOCOL_SOS  := plugins/libprot_modbus.so plugins/libprot_dnp3.so \
                 plugins/libprot_s7comm.so plugins/libprot_iec104.so plugins/libprot_opcua.so

# Default target
all: $(BIN) protocols

# Main protofire binary
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Main objects
fuzzer.o: fuzzer.c fuzzer_protocol.h grammar_fieldmap.h
	$(CC) $(CFLAGS) -c $< -o $@

fuzzer_protocol_common.o: fuzzer_protocol_common.c fuzzer_protocol.h
	$(CC) $(CFLAGS) -c $< -o $@

# Build protocol shared libraries
protocols: $(PROTOCOL_SOS)

# Shared library targets
plugins/libprot_%.so: plugins/%_module.o
	$(CC) -shared -fPIC -o $@ $<

# Compile protocol module object files
plugins/%_module.o: plugins/%_module.c fuzzer_protocol.h
	@mkdir -p plugins
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# Debug build
debug: CFLAGS += -DDEBUG -Og -ggdb3
debug: clean all

# Release build
release: CFLAGS += -DNDEBUG -O3 -flto
release: LDFLAGS += -flto
release: clean all

# Static analysis
analyze: clean
	scan-build --use-cc=$(CC) make

# Install folders for results
install: all
	mkdir -p crashes logs plugins
	@echo "protofire installed in current directory"
	@echo "Protocol plugins ready in ./plugins"

# Test plugin presence
test: all
	@echo "[*] Verifying protocol plugins..."
	@for proto in modbus dnp3 s7comm iec104 opcua; do \
		if [ -f "plugins/libprot_$$proto.so" ]; then \
			echo "✓ $$proto module OK"; \
		else \
			echo "✗ $$proto module missing"; \
		fi; \
	done
	@echo "[*] Build complete."

# Clean object and binary files
clean:
	rm -f $(OBJS) $(PROTOCOL_OBJS) $(BIN)
	rm -f $(PROTOCOL_SOS)

# Full reset
distclean: clean
	rm -rf crashes logs plugins

# Help text
help:
	@echo "protofire - Modular ICS Protocol Fuzzer v$(VERSION)"
	@echo
	@echo "Usage: make [target]"
	@echo
	@echo "Targets:"
	@echo "  all       - Build core fuzzer and protocol modules"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build with optimizations"
	@echo "  analyze   - Run static analysis with scan-build"
	@echo "  install   - Create runtime folders and install binary"
	@echo "  test      - Verify that all protocol modules were built"
	@echo "  clean     - Remove compiled objects and binary"
	@echo "  distclean - Full cleanup (removes crashes/logs/plugins)"
	@echo "  help      - Show this help message"

.PHONY: all protocols debug release analyze install test clean distclean help
