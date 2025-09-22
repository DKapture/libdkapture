PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
TARGET = $(BUILD_DIR)/libdkapture.so
CXX_SRC = $(wildcard *.cpp)
CXX_OBJ = $(CXX_SRC:%.cpp=$(BUILD_DIR)/%.o) \
		  $(BUILD_DIR)/trace-file.o \
		  $(BUILD_DIR)/kmemleak.o \
		  $(BUILD_DIR)/lsock.o \
		  $(BUILD_DIR)/mountsnoop.o \
		  $(BUILD_DIR)/irqsnoop.o

CXXFLAGS = -fPIC -Wall \
		   -I$(PROJ_ROOT)/include \
		   -I$(PROJ_ROOT)/build/observe \
		   -I$(PROJ_ROOT)/bpf/export

ifeq ($(Release),1)
	CXXFLAGS := -DNDEBUG -O2 $(CXXFLAGS)
else
	CXXFLAGS := -MMD -g -Og $(CXXFLAGS)
	LD_FLAGS += -Wl,-rpath=$(PROJ_ROOT)/build/so/
endif

LDFLAGS = -Wl,--no-as-needed -lbpf -shared

.PHONY: all so clean
.SECONDARY:
.SUFFIXES:

all so: $(TARGET)

$(TARGET): $(CXX_OBJ)
	g++ $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: $(PROJ_ROOT)/observe/%.cpp $(PROJ_ROOT)/build/observe/%.skel.h | $(BUILD_DIR)
	$(CXX) -DBUILTIN $(CXXFLAGS) -c $< -o $@

$(PROJ_ROOT)/build/observe/%:
	make -C $(PROJ_ROOT)/observe $@ SHARED_LIB=1

$(BUILD_DIR)/%.o: %.cpp $(PROJ_ROOT)/build/observe/proc-info.skel.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -f $(CXX_OBJ) $(BUILD_DIR)/*.d $(TARGET)

distclean: clean
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)