cmake_minimum_required(VERSION 3.13)
project(gwlbtun)
set(CMAKE_CXX_STANDARD 17)

# Default to an optimized build. Without this, the documented `cmake3 . && make` produced a
# binary with no -O flag at all, because -O3 is only set for the Release build type.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (Release, Debug, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

# Vendored header-only third-party libraries (Boost subset via bcp, nlohmann/json).
# SYSTEM so their headers don't trip our -Wall -Wextra -Wshadow=local, and so <boost/...> /
# <json/json.hpp> resolve (Boost headers cross-include via <boost/...>, which needs the
# vendor root on the include path). No external Boost install / find_package required.
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/third_party)

find_package(Threads REQUIRED)

# Get git commit information
execute_process(
    COMMAND git log -1 --format=%H
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_SHORT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

execute_process(
    COMMAND git describe --tags --always --dirty
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if(NOT GIT_COMMIT_HASH)
    set(GIT_COMMIT_HASH "unknown")
    set(GIT_COMMIT_SHORT "unknown")
    set(GIT_DESCRIBE "unknown")
endif()

# Get build timestamp
string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%d %H:%M:%S UTC" UTC)

# Configure version header
configure_file(
    ${CMAKE_SOURCE_DIR}/version.h.in
    ${CMAKE_BINARY_DIR}/version.h
    @ONLY
)

# -Wshadow=local (not bare -Wshadow): warn when a local/parameter shadows another
# local/parameter, but NOT when a parameter shadows a member or global. The codebase
# deliberately names constructor parameters after the members they initialize
# (member-init-list idiom, e.g. FlowCache / *HealthCheck ctors), which is safe; bare
# -Wshadow floods on that pattern and trains the warning to be ignored. =local keeps the
# signal that matters -- a local shadowing another local (the real footgun class).
# Appended rather than set, so flags passed by the user (CXXFLAGS or -DCMAKE_CXX_FLAGS=...,
# e.g. -DNO_RETURN_TRAFFIC) are kept.
string(APPEND CMAKE_CXX_FLAGS " -Wall -Wextra -Wshadow=local")
# -O3, not -Ofast: -Ofast adds -ffast-math (no floating point on the packet path to gain from it) and
# -fallow-store-data-races, which lets the compiler introduce stores that race with other threads.
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Debug: AddressSanitizer, at compile and link time.
set(CMAKE_CXX_FLAGS_DEBUG "-fstack-protector-all -fsanitize=address -fno-omit-frame-pointer -O0 -g")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")

add_executable(gwlbtun main.cpp GwlbtunConfig.cpp GwlbtunConfig.h UDPPacketReceiver.cpp UDPPacketReceiver.h GenevePacket.cpp GenevePacket.h TunInterface.cpp TunInterface.h utils.cpp utils.h PacketHeaderV4.cpp PacketHeaderV4.h PacketHeaderV6.cpp PacketHeaderV6.h GeneveHandler.cpp GeneveHandler.h FlowCache.h HookScripts.cpp HookScripts.h Logger.cpp Logger.h WorkerThread.h
        HealthCheck.h EbpfLoader.cpp EbpfLoader.h EbpfHelpers.h)
target_include_directories(gwlbtun PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(gwlbtun Threads::Threads)

# The eBPF datapath (-e): gwlbtun-ebpf.o, built from EbpfHelpers.c with clang, and gwlbtun linked with libbpf.
# GWLBTUN_EBPF=AUTO (the default) builds it if clang and libbpf-devel are installed, ON requires them, OFF skips
# it. Without it gwlbtun builds as before, with no libbpf dependency, and rejects -e.
set(GWLBTUN_EBPF AUTO CACHE STRING "Build the eBPF datapath (-e): AUTO, ON or OFF")
set_property(CACHE GWLBTUN_EBPF PROPERTY STRINGS AUTO ON OFF)
set(EBPF_BUILD OFF)
if(NOT GWLBTUN_EBPF STREQUAL "OFF")
    find_path(LIBBPF_INCLUDE_DIR NAMES bpf/libbpf.h)
    find_library(LIBBPF_LIBRARY NAMES bpf)
    find_program(CLANG_EXECUTABLE NAMES clang)
    if(LIBBPF_INCLUDE_DIR AND LIBBPF_LIBRARY AND CLANG_EXECUTABLE)
        set(EBPF_BUILD ON)
    elseif(GWLBTUN_EBPF STREQUAL "ON")
        message(FATAL_ERROR "GWLBTUN_EBPF=ON, but clang and libbpf-devel are needed to build the eBPF datapath.")
    endif()
endif()

if(EBPF_BUILD)
    message(STATUS "Building gwlbtun's eBPF datapath (gwlbtun-ebpf.o) with ${CLANG_EXECUTABLE} and ${LIBBPF_LIBRARY}")
    # clang -target bpf doesn't define the host architecture, so glibc's <gnu/stubs.h> would ask for the 32-bit
    # stubs, which 64-bit-only distributions such as Amazon Linux 2023 don't install. Say which 64-bit host it is.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        set(EBPF_ARCH_DEFINES -D__x86_64__ -D__LP64__)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(EBPF_ARCH_DEFINES -D__aarch64__ -D__LP64__)
    else()
        set(EBPF_ARCH_DEFINES -D__LP64__)
    endif()
    add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gwlbtun-ebpf.o
            COMMAND ${CLANG_EXECUTABLE} -O2 -g -Wall -Werror -target bpf ${EBPF_ARCH_DEFINES} -I${LIBBPF_INCLUDE_DIR}
                    -c ${CMAKE_CURRENT_SOURCE_DIR}/EbpfHelpers.c -o ${CMAKE_CURRENT_BINARY_DIR}/gwlbtun-ebpf.o
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/EbpfHelpers.c ${CMAKE_CURRENT_SOURCE_DIR}/EbpfHelpers.h
            COMMENT "Compiling the eBPF datapath (gwlbtun-ebpf.o)"
            VERBATIM)
    add_custom_target(gwlbtun-ebpf ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gwlbtun-ebpf.o)
    add_dependencies(gwlbtun gwlbtun-ebpf)
    target_include_directories(gwlbtun PRIVATE ${LIBBPF_INCLUDE_DIR})
    target_compile_definitions(gwlbtun PRIVATE ENABLE_EBPF)
    target_link_libraries(gwlbtun ${LIBBPF_LIBRARY})
else()
    if(GWLBTUN_EBPF STREQUAL "OFF")
        message(STATUS "gwlbtun's eBPF datapath (gwlbtun-ebpf.o, for -e) was not built: GWLBTUN_EBPF=OFF.")
    else()
        message(STATUS "gwlbtun's eBPF datapath (gwlbtun-ebpf.o, for -e) was not built: it needs clang and libbpf-devel.")
    endif()
endif()

# libyaml (third_party/libyaml, MIT) reads configuration files (-f). Its C sources are compiled into
# gwlbtun rather than linked from the system, so the binary doesn't need libyaml installed. Its include
# directory goes ahead of the system ones, so a system libyaml-devel can't shadow it. The library and
# GwlbtunConfig.cpp run once, at startup: optimise them for size, put each function in its own section,
# and let the linker drop what's unused (most of libyaml is the emitter). Packet-path files are unaffected.
set(LIBYAML_SOURCES
    third_party/libyaml/src/api.c    third_party/libyaml/src/reader.c  third_party/libyaml/src/scanner.c
    third_party/libyaml/src/parser.c third_party/libyaml/src/loader.c  third_party/libyaml/src/writer.c
    third_party/libyaml/src/emitter.c third_party/libyaml/src/dumper.c)
target_sources(gwlbtun PRIVATE ${LIBYAML_SOURCES})
target_include_directories(gwlbtun SYSTEM BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/third_party/libyaml/include)
set_source_files_properties(${LIBYAML_SOURCES} PROPERTIES
    COMPILE_OPTIONS "-Os;-ffunction-sections;-fdata-sections;-w"
    COMPILE_DEFINITIONS "YAML_DECLARE_STATIC;YAML_VERSION_MAJOR=0;YAML_VERSION_MINOR=2;YAML_VERSION_PATCH=5;YAML_VERSION_STRING=\"0.2.5\"")
set_source_files_properties(GwlbtunConfig.cpp PROPERTIES COMPILE_OPTIONS "-Os;-ffunction-sections;-fdata-sections")
target_link_options(gwlbtun PRIVATE "LINKER:--gc-sections")
