obj-m += ffn_ctlease.o
KDIR ?= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
client:
	$(CC) -D_GNU_SOURCE -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared ffn_ctlease_client.c -o libffn-ctlease.so
test: client
	$(CC) -std=c11 -Wall -Wextra -Werror ctlease_abi.c -o ctlease-abi
	sh ./test-kernel.sh
.PHONY: all client test
