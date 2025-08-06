TEST_SRC_C = $(wildcard *.c)
TEST_SRC_CPP = $(wildcard *.cpp)
TEST_OBJ = $(TEST_SRC_C:%.c=%.o) $(TEST_SRC_CPP:%.cpp=%.o)
TARGET = $(TEST_OBJ:%.o=%)
CXXFLAGS = -g -I$(PROJ_ROOT)/observe \
		   -I$(PROJ_ROOT)/include -I$(PROJ_ROOT)/filter \

.PHONY: all clean

all: $(TARGET)

clean:
	rm -f *.o $(TARGET)
