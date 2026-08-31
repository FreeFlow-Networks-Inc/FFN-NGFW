# FFN-NGFW -- top-level build.
#
# Builds the portable parts. The FPGA control-plane build (ngfwctl, ngfwd,
# libngfw) is not here: it lives in the FFN-NGFW-FPGA platform submodule
# alongside the proprietary library it links against.

.PHONY: all dataplanes dpdk test clean

# Plain `make` builds what works on any host, so it does not fail on a box
# without DPDK headers.
all: dataplanes

dataplanes:
	$(MAKE) -C dataplanes

dpdk:
	$(MAKE) -C dpdk

test:
	$(MAKE) -C dataplanes test

clean:
	$(MAKE) -C dataplanes clean
	-$(MAKE) -C dpdk clean
