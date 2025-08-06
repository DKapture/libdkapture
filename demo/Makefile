PROJ_ROOT ?= ..

CXX_FLAGS = -g -MMD
LD_FLAGS = -L$(PROJ_ROOT)/so/ -ldkapture -luuid
ifeq ($(DEBUG), 1)
	LD_FLAGS += -Wl,-rpath=$(PROJ_ROOT)/so/
endif

demo: demo.cpp $(PROJ_ROOT)/so/libdkapture.so
	g++ $(CXX_FLAGS) $< -I$(PROJ_ROOT)/include/ -o demo $(LD_FLAGS)

demo.cpp: $(PROJ_ROOT)/include/dkapture.h

$(PROJ_ROOT)/so/libdkapture.so:
	make -C $(PROJ_ROOT) so

.PHONY: $(PROJ_ROOT)/so/libdkapture.so clean

clean:
	rm -rf *.o *.d demo tmp dkapture-demo.tgz

-include $(wildcard *.d)
