cmake_minimum_required(VERSION 3.16)
project(net-speed-monitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# libdkapture root (default: parent directory)
set(DKAPTER_ROOT "${DKAPTER_ROOT}" CACHE PATH "Path to libdkapture source root")
if(NOT DKAPTER_ROOT)
    set(DKAPTER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
endif()

# Verify BPF artifacts exist
set(BPF_SKEL_H "${DKAPTER_ROOT}/build/observe/net-traffic.skel.h")
set(BPF_OBJ    "${DKAPTER_ROOT}/build/observe/net-traffic.bpf.o")

if(NOT EXISTS "${BPF_SKEL_H}" OR NOT EXISTS "${BPF_OBJ}")
    message(FATAL_ERROR
        "BPF artifacts not found. Please build libdkapture first:\n"
        "  cd ${DKAPTER_ROOT} && make bpf observe\n"
        "  Or set -DDKAPTER_ROOT=<path>\n"
        "  Expected: ${BPF_SKEL_H}\n"
        "  Expected: ${BPF_OBJ}")
endif()

add_executable(net-speed-monitor
    main.cpp
    bpf_worker.cpp
    speed_model.cpp
)

target_include_directories(net-speed-monitor PRIVATE
    "${DKAPTER_ROOT}/bpf/export"
    "${DKAPTER_ROOT}/build/observe"
)

target_link_libraries(net-speed-monitor PRIVATE
    Qt6::Widgets
    bpf
    pthread
    elf
)
