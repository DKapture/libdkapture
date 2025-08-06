

PWD = $(shell pwd)

obj-m := retreat-exe.o retreat-file.o

all module:
	@echo $(obj-m)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean