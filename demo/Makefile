PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
TARGET = $(BUILD_DIR)/demo
CXXFLAGS = -I$(PROJ_ROOT)/include/ \
			-I$(PROJ_ROOT)/build/include/ \
			-I$(PROJ_ROOT)/bpf/export
LD_FLAGS = -L$(PROJ_ROOT)/build/so/ -ldkapture

ifeq ($(Release),1)
	CXXFLAGS := -DNDEBUG -O2 $(CXXFLAGS)
else
	CXXFLAGS := -MMD -g -Og $(CXXFLAGS)
	LD_FLAGS += -Wl,-rpath=$(PROJ_ROOT)/build/so/
endif

all: $(TARGET)

$(BUILD_DIR)/%: $(BUILD_DIR)/%.o $(PROJ_ROOT)/build/so/libdkapture.so | $(BUILD_DIR)
	g++ $(CXXFLAGS) $< -I$(PROJ_ROOT)/include/ -o $@ $(LD_FLAGS)

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	g++ $(CXXFLAGS) -c $< -o $@

$(PROJ_ROOT)/build/so/libdkapture.so: | $(BUILD_DIR)
	make -C $(PROJ_ROOT) so
	
$(BUILD_DIR):
	@mkdir -p $@

.PHONY: all clean distclean
.SECONDARY:

clean:
	rm -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(TARGET)

distclean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)
