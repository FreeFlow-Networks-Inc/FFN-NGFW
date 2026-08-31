# FFN OCTEON-II dataplane
#
#   make            native build + test (x86-64, proves the logic)
#   make test       run the test harness
#   make mips64     cross-build for OCTEON-II (big-endian MIPS64)
#   make qemu-test  run the SAME test under qemu-mips64 (validates big-endian)
#
# The forwarder has no chip headers, so the native and MIPS builds compile the
# identical sources; only the packet-I/O backend differs on real hardware.

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
SRC      = ffn_dp_oct.c
TEST_SRC = ffn_dp_oct_test.c
HDRS     = ffn_dp_abi.h ffn_dp_oct.h

# OCTEON-II: MIPS64 release 2, BIG-endian. Upstream toolchain preferred over the
# Cavium SDK (licence hygiene -- FFN ships nothing SDK-derived).
MIPS_CC     ?= mips64-linux-gnuabi64-gcc
MIPS_CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 \
               -march=mips64r2 -mabi=64 -EB -static

AFP_SRC  = ffn_dp_io_afpacket.c
AFP_MAIN = ffn_dp_afpacket_main.c
AFP_HDRS = $(HDRS) ffn_dp_io_afpacket.h

all: ffn_dp_oct_test ffn_dp_afpacket

ffn_dp_oct.o: $(SRC) $(HDRS)
	$(CC) $(CFLAGS) -c $(SRC) -o $@

ffn_dp_oct_test: ffn_dp_oct.o $(TEST_SRC) $(HDRS)
	$(CC) $(CFLAGS) ffn_dp_oct.o $(TEST_SRC) -o $@

test: ffn_dp_oct_test
	./ffn_dp_oct_test

# runnable dataplane over real Linux interfaces (Linux-only backend)
ffn_dp_afpacket: ffn_dp_oct.o $(AFP_SRC) $(AFP_MAIN) $(AFP_HDRS)
	$(CC) $(CFLAGS) ffn_dp_oct.o $(AFP_SRC) $(AFP_MAIN) -o $@

# end-to-end forwarding test over veth pairs (needs root)
veth-test: ffn_dp_afpacket
	./veth_test.sh

# --- OCTEON-II hardware backend (IPD/PIP + POW + PKO) ---
# Built WITHOUT the SDK by default: the hardware seam compiles and reports the
# backend unavailable, and the mock-hardware test still verifies the FPA
# buffer-ownership contract. To build the real path, supply an OCTEON SDK:
#   make oct-test CVMX=1 CVMX_INC=-I/path/to/octeon-sdk/target/include
OCT_SRC  = ffn_dp_io_octeon.c
OCT_TEST = ffn_dp_io_octeon_test.c
OCT_HDRS = $(HDRS) ffn_dp_io_octeon.h
ifdef CVMX
OCT_CFLAGS = -DFFN_HAVE_CVMX $(CVMX_INC)
else
OCT_CFLAGS =
endif

ffn_dp_oct_io_test: ffn_dp_oct.o $(OCT_SRC) $(OCT_TEST) $(OCT_HDRS)
	$(CC) $(CFLAGS) $(OCT_CFLAGS) ffn_dp_oct.o $(OCT_SRC) $(OCT_TEST) -o $@

oct-test: ffn_dp_oct_io_test
	./ffn_dp_oct_io_test

# --- OCTEON-III backend (PKI + SSO + PKO3) ---
# The PA-5220's CN73XX is OCTEON-III. This backend lives alongside the OCTEON-II
# one (a PA-3200 needs that) and is selected at runtime by oct_detect_gen().
OCT3_SRC  = ffn_dp_io_octeon3.c
OCT3_TEST = ffn_dp_io_octeon3_test.c
OCT3_HDRS = $(HDRS) ffn_dp_io_octeon.h ffn_dp_io_octeon3.h

ffn_dp_oct3_io_test: ffn_dp_oct.o $(OCT_SRC) $(OCT3_SRC) $(OCT3_TEST) $(OCT3_HDRS)
	$(CC) $(CFLAGS) $(OCT_CFLAGS) ffn_dp_oct.o $(OCT_SRC) $(OCT3_SRC) $(OCT3_TEST) 	    -o $@

oct3-test: ffn_dp_oct3_io_test
	./ffn_dp_oct3_io_test

# The aura/descriptor logic is endianness-sensitive, and the real target is
# big-endian MIPS64, so the same suite runs there too.
oct3-qemu: $(SRC) $(OCT_SRC) $(OCT3_SRC) $(OCT3_TEST) $(OCT3_HDRS)
	@command -v $(MIPS_CC) >/dev/null 2>&1 || { echo "MISSING $(MIPS_CC)"; exit 1; }
	$(MIPS_CC) $(MIPS_CFLAGS) $(OCT_CFLAGS) $(SRC) $(OCT_SRC) $(OCT3_SRC) 	    $(OCT3_TEST) -o ffn_dp_oct3_io_test.mips64
	qemu-mips64 ./ffn_dp_oct3_io_test.mips64

# same backend test, big-endian, as it will run on the real Octeon
oct-qemu: $(SRC) $(OCT_SRC) $(OCT_TEST) $(OCT_HDRS)
	@command -v $(MIPS_CC) >/dev/null 2>&1 || { echo "MISSING $(MIPS_CC)"; exit 1; }
	$(MIPS_CC) $(MIPS_CFLAGS) $(OCT_CFLAGS) $(SRC) $(OCT_SRC) $(OCT_TEST) \
	    -o ffn_dp_oct_io_test.mips64
	qemu-mips64 ./ffn_dp_oct_io_test.mips64

# everything that can run without Octeon hardware
check: test oct-test oct3-test
	@echo "--- big-endian ---"
	@$(MAKE) -s qemu-test
	@$(MAKE) -s oct-qemu
	@$(MAKE) -s oct3-qemu

# --- cross build for the real target ---
mips64: $(SRC) $(TEST_SRC) $(HDRS)
	@command -v $(MIPS_CC) >/dev/null 2>&1 || { \
	  echo "MISSING $(MIPS_CC)"; \
	  echo "  Debian/Ubuntu: apt install gcc-mips64-linux-gnuabi64"; \
	  echo "  (or a Buildroot OCTEON-II toolchain)"; exit 1; }
	$(MIPS_CC) $(MIPS_CFLAGS) $(SRC) $(TEST_SRC) -o ffn_dp_oct_test.mips64
	@file ffn_dp_oct_test.mips64

# Same expectations, big-endian: catches any accidental native-endian access.
qemu-test: mips64
	@command -v qemu-mips64 >/dev/null 2>&1 || { \
	  echo "MISSING qemu-mips64 (apt install qemu-user)"; exit 1; }
	qemu-mips64 ./ffn_dp_oct_test.mips64

clean:
	$(RM) ffn_dp_oct.o ffn_dp_oct_test ffn_dp_oct_test.mips64 ffn_dp_afpacket \
	      ffn_dp_oct_io_test ffn_dp_oct_io_test.mips64 \
      ffn_dp_oct3_io_test ffn_dp_oct3_io_test.mips64

.PHONY: all test mips64 qemu-test veth-test oct-test oct-qemu oct3-test oct3-qemu check clean
