cmake_minimum_required(VERSION 3.13)
project(gwlbtun)
set(CMAKE_CXX_STANDARD 17)

# Vendored header-only third-party libraries (Boost subset via bcp, nlohmann/json).
# SYSTEM so their headers don't trip our -Wall -Wextra -Wshadow=local, and so <boost/...> /
# <json/json.hpp> resolve (Boost headers cross-include via <boost/...>, which needs the
# vendor root on the include path). No external Boost install / find_package required.
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/third_party)

find_package(Threads)

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

# Check if working directory is clean
execute_process(
    COMMAND git diff-index --quiet HEAD --
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    RESULT_VARIABLE GIT_DIRTY
    ERROR_QUIET
)

if(NOT GIT_COMMIT_HASH)
    set(GIT_COMMIT_HASH "unknown")
    set(GIT_COMMIT_SHORT "unknown")
    set(GIT_DESCRIBE "unknown")
endif()

if(GIT_DIRTY)
    set(GIT_DIRTY_FLAG "-dirty")
else()
    set(GIT_DIRTY_FLAG "")
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
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow=local")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")

set(CMAKE_CXX_FLAGS_DEBUG "-fstack-protector-all -fsanitize=address -pg -O0 -g")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-lasan")

add_compile_options("")

add_executable(gwlbtun main.cpp UDPPacketReceiver.cpp UDPPacketReceiver.h GenevePacket.cpp GenevePacket.h TunInterface.cpp TunInterface.h utils.cpp utils.h PacketHeaderV4.cpp PacketHeaderV4.h PacketHeaderV6.cpp PacketHeaderV6.h GeneveHandler.cpp GeneveHandler.h FlowCache.h FlowCacheHealthCheck.cpp Logger.cpp Logger.h
        HealthCheck.h
        FlowCacheHealthCheck.cpp
        EbpfLoader.cpp EbpfLoader.h EbpfHelpers.h GeneveStructs.h)
target_include_directories(gwlbtun PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries (gwlbtun ${CMAKE_THREAD_LIBS_INIT})

# ------------------------------------------------------------------
# Optional eBPF/XDP acceleration.
# If libbpf and clang are present, compile the XDP program (gwlbtun-ebpf.o) and
# build gwlbtun with eBPF support (ENABLE_EBPF). Otherwise gwlbtun builds normally
# and every packet is processed in userspace.
# ------------------------------------------------------------------
find_path(LIBBPF_INCLUDE_DIRS NAMES bpf/libbpf.h)
find_library(LIBBPF_LIBRARIES NAMES bpf)
find_program(CLANG_EXECUTABLE NAMES clang)

if(LIBBPF_INCLUDE_DIRS AND LIBBPF_LIBRARIES AND CLANG_EXECUTABLE)
    message(STATUS "eBPF support enabled (libbpf: ${LIBBPF_LIBRARIES}, clang: ${CLANG_EXECUTABLE})")

    # `clang -target bpf` does not define the host architecture macros, so glibc's
    # <gnu/stubs.h> (pulled in transitively via standard headers) falls through to
    # the 32-bit stub <gnu/stubs-32.h>. That stub is not installed on 64-bit-only
    # distros such as Amazon Linux 2023 (glibc-devel.i686 / i686 multilib is not
    # available), so the BPF compile fails with "'gnu/stubs-32.h' file not found".
    # Define the host arch + __LP64__ so stubs.h selects the present 64-bit stub.
    # Kept arch-portable because gwlbtun also builds on Graviton (aarch64).
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        set(EBPF_ARCH_DEFINES -D__x86_64__ -D__LP64__)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(EBPF_ARCH_DEFINES -D__aarch64__ -D__LP64__)
    else()
        set(EBPF_ARCH_DEFINES -D__LP64__)
    endif()

    # Compile the eBPF program (tc clsact ingress + egress) to a BPF object file.
    add_custom_target(gwlbtun-ebpf.o ALL
            COMMAND ${CLANG_EXECUTABLE} -O2 -g -Wall -target bpf ${EBPF_ARCH_DEFINES} -c ${CMAKE_CURRENT_SOURCE_DIR}/EbpfHelpers.c -o ${CMAKE_CURRENT_BINARY_DIR}/gwlbtun-ebpf.o
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/EbpfHelpers.c ${CMAKE_CURRENT_SOURCE_DIR}/EbpfHelpers.h ${CMAKE_CURRENT_SOURCE_DIR}/GeneveStructs.h
            COMMENT "Compiling eBPF program (gwlbtun-ebpf.o)"
            VERBATIM)
    add_dependencies(gwlbtun gwlbtun-ebpf.o)

    target_include_directories(gwlbtun PRIVATE ${LIBBPF_INCLUDE_DIRS})
    target_compile_definitions(gwlbtun PRIVATE ENABLE_EBPF)
    target_link_libraries(gwlbtun ${LIBBPF_LIBRARIES})

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gwlbtun-ebpf.o
            DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/gwlbtun
            PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
else()
    message(STATUS "eBPF support disabled (needs libbpf-devel and clang). gwlbtun will process all packets in userspace.")
endif()
