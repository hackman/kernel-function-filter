obj-m := block-functions.o livepatch-filter.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Note: when insmod'd, ".ko" files with '-' in their names register
# under module names where '-' is replaced by '_'.
FT_MOD := block_functions
LP_MOD := livepatch_filter

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load-ftrace: all
	sudo insmod block-functions.ko

unload-ftrace:
	sudo rmmod $(FT_MOD)

load-livepatch: all
	sudo insmod livepatch-filter.ko

unload-livepatch:
	echo 0 | sudo tee /sys/kernel/livepatch/$(LP_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(LP_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(LP_MOD)

.PHONY: all clean load-ftrace unload-ftrace load-livepatch unload-livepatch
