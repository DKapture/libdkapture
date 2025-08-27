PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
LOCAL_CPP = $(wildcard *.cpp)
LOCAL_OBJS = $(LOCAL_CPP:%.cpp=$(BUILD_DIR)/%.o)
REMOTE_CPP = $(wildcard $(PROJ_ROOT)/so/*.cpp)
REMOTE_OBJS := $(notdir $(REMOTE_CPP))
REMOTE_OBJS := $(REMOTE_OBJS:%.cpp=$(BUILD_DIR)/%.o)
OBJS = $(LOCAL_OBJS) $(REMOTE_OBJS)

TARGET = $(BUILD_DIR)/dkapture-test

CXXFLAGS = -g -D__GTEST__ -DBUILTIN -MMD \
		   -I$(PROJ_ROOT)/observe -I$(PROJ_ROOT)/so \
		   -I$(PROJ_ROOT)/include -I$(PROJ_ROOT)/observe \
		   -I$(PROJ_ROOT)/googletest/googletest/include \
		   -I$(PROJ_ROOT)/build/include \
		   -I$(PROJ_ROOT)/build/observe \
		   -I$(PROJ_ROOT)/build/policy

LDFLAGS = -Wl,-rpath=$(PROJ_ROOT)/googletest/build/lib/ -luuid

GTEST_LIBS = $(PROJ_ROOT)/googletest/build/lib/libgtest_main.so	\
			 $(PROJ_ROOT)/googletest/build/lib/libgtest.so
GTEST_HDRS = $(PROJ_ROOT)/googletest/googletest/include
CC = gcc
CXX = g++

.PHONY: all clean distclean
.SECONDARY:
.SUFFIXES:

all: $(TARGET)

$(TARGET): $(OBJS) $(GTEST_LIBS) \
	$(BUILD_DIR)/trace-file.o \
	$(BUILD_DIR)/lsock.o \
	$(BUILD_DIR)/kmemleak.o \
	$(BUILD_DIR)/irqsnoop.o \
	$(BUILD_DIR)/mountsnoop.o \
	$(BUILD_DIR)/frtp.o
	$(CXX) $^ $(LDFLAGS) -o $@

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%.o: $(PROJ_ROOT)/so/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.cpp $(GTEST_HDRS) $(PROJ_ROOT)/build/observe/proc-info.skel.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(PROJ_ROOT)/observe/%.cpp $(PROJ_ROOT)/build/observe/%.skel.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(PROJ_ROOT)/policy/%.cpp $(PROJ_ROOT)/build/policy/%.skel.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(PROJ_ROOT)/build/observe/%:
	make -C $(PROJ_ROOT)/observe $@ SHARED_LIB=1

$(PROJ_ROOT)/build/policy/%:
	make -C $(PROJ_ROOT)/policy $@ SHARED_LIB=1

$(PROJ_ROOT)/googletest/build/lib/libgtest_main.so: $(PROJ_ROOT)/googletest/build/lib/libgtest.so

$(GTEST_LIBS): $(GTEST_HDRS)
	cd $(PROJ_ROOT)/googletest && mkdir -p build && cd build && \
	cmake ../ -DBUILD_SHARED_LIBS=ON && make -j4

$(GTEST_HDRS):
	cd $(PROJ_ROOT) && git submodule update --init --recursive --depth 1

clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(TARGET)

distclean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)
