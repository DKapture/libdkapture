PROJ_ROOT ?= ..
LOCAL_CPP = $(wildcard *.cpp)
REMOTE_CPP = $(wildcard $(PROJ_ROOT)/so/*.cpp)
LOCAL_OBJS = $(LOCAL_CPP:%.cpp=%.o)
REMOTE_OBJS = $(REMOTE_CPP:%.cpp=%.o)
REMOTE_OBJS := $(notdir $(REMOTE_OBJS))
OBJS = $(LOCAL_OBJS) $(REMOTE_OBJS)

TARGET = dkapture-test

CXXFLAGS = -g -D__GTEST__ -DBUILTIN -MMD \
		   -I$(PROJ_ROOT)/observe -I$(PROJ_ROOT)/so \
		   -I$(PROJ_ROOT)/include -I$(PROJ_ROOT)/observe \
		   -I$(PROJ_ROOT)/googletest/googletest/include

LDFLAGS = -Wl,-rpath=$(PROJ_ROOT)/googletest/build/lib/ -luuid

GTEST_LIBS = $(PROJ_ROOT)/googletest/build/lib/libgtest_main.so	\
			 $(PROJ_ROOT)/googletest/build/lib/libgtest.so
GTEST_HDRS = $(PROJ_ROOT)/googletest/googletest/include
CC = gcc
CXX = g++

.PHONY: all clean
.PRECIOUS: $(PROJ_ROOT)/observe/proc-info.skel.h
# .SECONDARY:
.SUFFIXES:

$(TARGET): $(OBJS) $(GTEST_LIBS) \
	$(PROJ_ROOT)/test/trace-file.o \
	$(PROJ_ROOT)/test/lsock.o \
	$(PROJ_ROOT)/test/kmemleak.o \
	$(PROJ_ROOT)/test/irqsnoop.o \
	$(PROJ_ROOT)/test/mountsnoop.o
	$(CXX) $^ $(LDFLAGS) -o $@

%.o: $(PROJ_ROOT)/so/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.cpp $(GTEST_HDRS) $(PROJ_ROOT)/observe/proc-info.skel.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(PROJ_ROOT)/test/%.o: $(PROJ_ROOT)/observe/%.cpp $(PROJ_ROOT)/observe/%.skel.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(PROJ_ROOT)/observe/%:
	make -C $(PROJ_ROOT)/observe $* SHARED_LIB=1

$(PROJ_ROOT)/googletest/build/lib/libgtest_main.so: $(PROJ_ROOT)/googletest/build/lib/libgtest.so

$(GTEST_LIBS): $(GTEST_HDRS)
	cd $(PROJ_ROOT)/googletest && mkdir -p build && cd build && \
	cmake ../ -DBUILD_SHARED_LIBS=ON && make -j4

$(GTEST_HDRS): 
	cd $(PROJ_ROOT) && git submodule update --init --recursive

clean:
	rm -f *.o *.d $(TARGET)

-include $(wildcard *.d)
