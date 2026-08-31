#
# libngfw — shared library
#

LIB_MAJOR   := 1
LIB_MINOR   := 0
LIB_PATCH   := 0
LIB_NAME    := libngfw
SONAME      := $(LIB_NAME).so.$(LIB_MAJOR)
SHLIB       := $(LIB_NAME).so.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)

SRCDIR      := src
INCDIR      := include
BUILDDIR    := build

CFLAGS      ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS      += -fPIC -I$(INCDIR) -std=c99 -D_GNU_SOURCE
LDFLAGS     += -shared -Wl,-soname,$(SONAME)

SRCS        := $(wildcard $(SRCDIR)/*.c)
OBJS        := $(SRCS:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)

PREFIX      ?= /usr/local
INCLUDEDIR  := $(PREFIX)/include/ngfw
LIBDIR      := $(PREFIX)/lib

.PHONY: all clean install

all: $(BUILDDIR)/$(SHLIB)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(SHLIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	cd $(BUILDDIR) && ln -sf $(SHLIB) $(SONAME) && ln -sf $(SONAME) $(LIB_NAME).so

install: all
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 755 $(BUILDDIR)/$(SHLIB) $(DESTDIR)$(LIBDIR)/
	cd $(DESTDIR)$(LIBDIR) && \
	  ln -sf $(SHLIB) $(SONAME) && \
	  ln -sf $(SONAME) $(LIB_NAME).so
	install -m 644 $(INCDIR)/ngfw/ngfw.h      $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 $(INCDIR)/ngfw/ngfw_regs.h $(DESTDIR)$(INCLUDEDIR)/
	ldconfig

clean:
	rm -rf $(BUILDDIR)
