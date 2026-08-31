TARGET   := ngfwd
CFLAGS   ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS   += -std=c99 -D_GNU_SOURCE
CFLAGS   += -I../../libngfw/include
LDFLAGS  += -L../../libngfw/build -lngfw -lpthread

PREFIX   ?= /usr/local

$(TARGET): ngfwd.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: install clean
