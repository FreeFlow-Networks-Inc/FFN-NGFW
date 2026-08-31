# SPDX-License-Identifier: GPL-2.0-or-later
# Makefile -- FFN-NGFW Pass-2 DPDK data plane (box build, SIDE-BY-SIDE deps).
#
# Target box facts (do NOT assume system paths):
#   DPDK 22.11 -> prefix /opt/dpdk-22.11
#                 pkg-config: /opt/dpdk-22.11/lib/x86_64-linux-gnu/pkgconfig/libdpdk.pc
#   flatcc     -> prefix /opt/flatcc
#                 bin/flatcc, include/, lib/libflatccrt.a
#   Hyperscan  -> pkg-config libhs (OPTIONAL; compiled behind HAVE_HYPERSCAN)
#
# Builds three binaries:
#   ffn-fastpath-fwd : standalone DPDK-primary fast path
#                      (ffn_fastpath_fwd.c + ffn_mpdp_consumer.c + flatcc rt)
#   ffn-dpdk-mp      : symmetric-MP + zygote data plane
#                      (ffn_dpdk_mp.c + ffn_fastpath_fwd.c worker + ffn_mpdp_consumer.c, -pthread)
#   ffn_hs_build     : the one libhs-gated Hyperscan DB serializer (unchanged)
#
# Flatcc codegen turns ../ngfwd/ffn_mpdp.fbs into the C reader/builder/verifier
# headers that ffn_mpdp_consumer.c #includes.
#
#   verify deps:   make check
#   build all:     make            (== make all)
#   codegen only:  make codegen
#   no-dpmem:      make FFN_NO_DPMEM=1   (static-tables-only ffn-fastpath-fwd)
#   clean:         make clean
#
# See PASS2_BUILD.md for the full box bring-up checklist.
# ---------------------------------------------------------------------------

CC         ?= cc

# ---- side-by-side dependency prefixes --------------------------------------
DPDK_PREFIX   ?= /opt/dpdk-22.11
DPDK_PCDIR    ?= $(DPDK_PREFIX)/lib/x86_64-linux-gnu/pkgconfig
FLATCC_PREFIX ?= /opt/flatcc
FLATCC        ?= $(FLATCC_PREFIX)/bin/flatcc
FLATCC_INC    := $(FLATCC_PREFIX)/include
FLATCC_RT     ?= $(FLATCC_PREFIX)/lib/libflatccrt.a

# pkg-config wrapper that always sees the side-by-side DPDK prefix first while
# preserving any PKG_CONFIG_PATH already in the environment. Used from both
# $(shell ...) (below) and recipe lines (check target).
PKG_CONFIG ?= pkg-config
PC         := PKG_CONFIG_PATH="$(DPDK_PCDIR):$$PKG_CONFIG_PATH" $(PKG_CONFIG)

# ---- DPDK 22.11 (required) -------------------------------------------------
DPDK_CFLAGS := $(shell $(PC) --cflags libdpdk)
DPDK_LIBS   := $(shell $(PC) --libs libdpdk)

# ---- Hyperscan (optional) --------------------------------------------------
# Auto-enabled when pkg-config knows libhs; force off with HAVE_HYPERSCAN=0.
HAVE_HYPERSCAN ?= $(shell $(PC) --exists libhs && echo 1 || echo 0)
ifeq ($(HAVE_HYPERSCAN),1)
HS_CFLAGS := -DHAVE_HYPERSCAN $(shell $(PC) --cflags libhs)
HS_LIBS   := $(shell $(PC) --libs libhs)
else
HS_CFLAGS :=
HS_LIBS   :=
endif

# ---- static-tables-only build (no DP-MP dpmem hot-swap) --------------------
# FFN_NO_DPMEM=1 compiles ffn_fastpath_fwd.c without ffn_dpmem.h (its hot-swap
# path is #ifndef FFN_NO_DPMEM). No-op for TUs that use dpmem unconditionally.
ifeq ($(FFN_NO_DPMEM),1)
DPMEM_DEF := -DFFN_NO_DPMEM
else
DPMEM_DEF :=
endif

# ---- aggregate flags -------------------------------------------------------
# -I.               : this dir -- finds ffn_dpmem.h (review flagged this) + the
#                     flatcc-generated headers (emitted into '.').
# -I$(FLATCC_INC)   : flatcc runtime headers (flatcc/flatcc_*.h, prologue, etc.)
CFLAGS  += -std=gnu11 -O2 -g -Wall -Wextra \
           -I. -I$(FLATCC_INC) \
           $(DPDK_CFLAGS) $(HS_CFLAGS) $(DPMEM_DEF)
# Objects first, then the flatcc static runtime, then DPDK + Hyperscan libs.
LDLIBS  += $(DPDK_LIBS) $(HS_LIBS)

# ---- flatcc codegen (../ngfwd/ffn_mpdp.fbs -> reader/builder/verifier) ------
FBS        := ../ngfwd/ffn_mpdp.fbs
# `flatcc -a` (== reader+builder+verifier+json) emits, for schema ffn_mpdp.fbs
# (flatcc 0.6.x canonical names -- the reader is ffn_mpdp_reader.h, NOT
# ffn_mpdp.h; the builder/verifier #include the reader). These match the
# #include lines already in ffn_mpdp_consumer.c, so NO source edit is needed.
GEN_READER := ffn_mpdp_reader.h
GEN_HDRS   := ffn_mpdp_reader.h ffn_mpdp_builder.h ffn_mpdp_verifier.h \
              ffn_mpdp_json_parser.h ffn_mpdp_json_printer.h \
              flatbuffers_common_reader.h flatbuffers_common_builder.h

# `make` with no target must build the binaries, not just `codegen` (which is
# the first target and would otherwise be the default goal).
.DEFAULT_GOAL := all

# One flatcc invocation produces the whole set; track the reader as the stamp.
$(GEN_READER): $(FBS)
	$(FLATCC) -a -o . $(FBS)

codegen: $(GEN_READER)

# ---- objects ---------------------------------------------------------------
# ffn_mpdp_consumer.o : shared by both binaries; needs the generated headers.
ffn_mpdp_consumer.o: ffn_mpdp_consumer.c $(GEN_READER) ffn_fastpath.h ffn_mpdp_consumer.h ffn_dpmem.h
	$(CC) $(CFLAGS) -c $< -o $@

# ffn_fastpath_fwd.o : standalone fast path -- keeps its own main().
ffn_fastpath_fwd.o: ffn_fastpath_fwd.c ffn_fastpath.h ffn_dpmem.h
	$(CC) $(CFLAGS) -c $< -o $@

# ffn_fastpath_fwd.mp.o : same TU for the MP binary. -DFFN_BUILD_MP compiles out
# this TU's standalone main() (guarded #ifndef FFN_BUILD_MP) so it does not
# collide with ffn_dpdk_mp.c's main(); the MP build links ffn_dpdk_mp.c's main()
# plus the strong ffn_dp_worker_run() this TU exports for the zygote workers.
ffn_fastpath_fwd.mp.o: ffn_fastpath_fwd.c ffn_fastpath.h ffn_dpmem.h
	$(CC) $(CFLAGS) -DFFN_BUILD_MP -c $< -o $@

# ffn_dpdk_mp.o : zygote/primary -- rte_ctrl_thread_create + pthread_join.
ffn_dpdk_mp.o: ffn_dpdk_mp.c ffn_dpmem.h ffn_fastpath.h
	$(CC) $(CFLAGS) -pthread -c $< -o $@

# ---- binaries --------------------------------------------------------------
all: ffn-fastpath-fwd ffn-dpdk-mp ffn_hs_build

ffn-fastpath-fwd: ffn_fastpath_fwd.o ffn_mpdp_consumer.o
	$(CC) $(CFLAGS) $^ -o $@ $(FLATCC_RT) $(LDLIBS)

ffn-dpdk-mp: ffn_dpdk_mp.o ffn_fastpath_fwd.mp.o ffn_mpdp_consumer.o
	$(CC) $(CFLAGS) -pthread $^ -o $@ $(FLATCC_RT) $(LDLIBS)

# Preserved: the libhs serialized-DB builder. Always needs Hyperscan (uses
# hs/hs.h + hs_compile_ext_multi unconditionally) -- independent of the app
# HAVE_HYPERSCAN toggle. Usage: ./ffn_hs_build <fastpath_dir>
ffn_hs_build: ffn_hs_build.c
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra $(shell $(PC) --cflags libhs) \
	      $< -o $@ $(shell $(PC) --libs libhs)

# ---- dependency sanity check ----------------------------------------------
check:
	@echo "== FFN-NGFW Pass-2 dependency check =="
	@echo "PKG_CONFIG_PATH prepend: $(DPDK_PCDIR)"
	@printf 'DPDK (libdpdk): '; $(PC) --modversion libdpdk \
	  || { echo "NOT FOUND -- is DPDK 22.11 installed at $(DPDK_PREFIX)?"; exit 1; }
	@printf 'Hyperscan (libhs): '; $(PC) --modversion libhs 2>/dev/null \
	  && echo "  -> HAVE_HYPERSCAN=$(HAVE_HYPERSCAN)" \
	  || echo "not found (app builds without inline content scan)"
	@printf 'flatcc CLI: '; test -x $(FLATCC) && $(FLATCC) --version \
	  || { echo "MISSING at $(FLATCC)"; exit 1; }
	@printf 'flatcc runtime: '; test -f $(FLATCC_RT) && echo "$(FLATCC_RT)" \
	  || { echo "MISSING at $(FLATCC_RT)"; exit 1; }
	@echo "== ok =="

clean:
	$(RM) ffn-fastpath-fwd ffn-dpdk-mp ffn_hs_build \
	      ffn_fastpath_fwd.o ffn_fastpath_fwd.mp.o ffn_dpdk_mp.o ffn_mpdp_consumer.o \
	      $(GEN_HDRS)

.PHONY: all codegen check clean
