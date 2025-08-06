PROJ_ROOT ?= ..
CXX_SRC = $(wildcard *.cpp)
CXX_OBJ = $(CXX_SRC:%.cpp=%.o) \
		$(PROJ_ROOT)/so/trace-file.o \
		$(PROJ_ROOT)/so/kmemleak.o \
		$(PROJ_ROOT)/so/lsock.o \
		$(PROJ_ROOT)/so/mountsnoop.o \
		$(PROJ_ROOT)/so/irqsnoop.o

CXXFLAGS = -g -O2 -fPIC -MMD	\
		   -I$(PROJ_ROOT)/include -I$(PROJ_ROOT)/observe -Wall
LDFLAGS = -Wl,--no-as-needed -lbpf -shared

.PHONY: all clean
.PRECIOUS: $(PROJ_ROOT)/observe/proc-info.skel.h
.SUFFIXES:

all so: $(CXX_OBJ) $(PROJ_ROOT)/observe/proc-info.skel.h
	g++ $(LDFLAGS) $^ -o libdkapture.so

$(PROJ_ROOT)/so/%.o: $(PROJ_ROOT)/observe/%.cpp $(PROJ_ROOT)/observe/%.skel.h
	$(CXX) -DBUILTIN $(CXXFLAGS) -c $< -o $@

$(PROJ_ROOT)/observe/%:
	make -C $(PROJ_ROOT)/observe $* SHARED_LIB=1

%.o: %.cpp $(PROJ_ROOT)/observe/proc-info.skel.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(CXX_OBJ) *.o *.d libdkapture.so

-include $(wildcard *.d)