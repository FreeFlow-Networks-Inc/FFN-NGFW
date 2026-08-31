# FFN-NGFW-FPGA Control Plane Software
# Build: make
# Install: sudo make install

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS =

PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin
CONFDIR = /etc/ngfw

.PHONY: all clean install

all: ngfwctl

ngfwctl: ngfwctl.c ngfw_regs.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f ngfwctl

install: ngfwctl
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	install -m 755 ngfwctl $(DESTDIR)$(BINDIR)/
	@echo "Installed ngfwctl to $(BINDIR)"
	@echo "Config dir: $(CONFDIR)"
	@echo ""
	@echo "Quick start:"
	@echo "  ngfwctl status              # check FPGA status"
	@echo "  ngfwctl engine list         # show engine enable state"
	@echo "  ngfwctl port enable 0 1 2 3 # enable all ports"
	@echo "  ngfwctl db load appid /etc/ngfw/appid.db"
