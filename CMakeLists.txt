cmake_minimum_required(VERSION 3.13)
project(gwlbtun)
set(CMAKE_CXX_STANDARD 17)

# Suppress FindBoost deprecation warning in CMake 3.30+
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

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

set(Boost_INCLUDE_DIR /home/ec2-user/boost)
find_package(Boost 1.83 REQUIRED)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")

set(CMAKE_CXX_FLAGS_DEBUG "-fstack-protector-all -fsanitize=address -pg -O0 -g")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-lasan")

add_compile_options("")

add_executable(gwlbtun main.cpp UDPPacketReceiver.cpp UDPPacketReceiver.h GenevePacket.cpp GenevePacket.h TunInterface.cpp TunInterface.h utils.cpp utils.h PacketHeaderV4.cpp PacketHeaderV4.h PacketHeaderV6.cpp PacketHeaderV6.h GeneveHandler.cpp GeneveHandler.h FlowCache.h FlowCacheHealthCheck.cpp Logger.cpp Logger.h
        HealthCheck.h
        FlowCacheHealthCheck.cpp)
target_include_directories(gwlbtun PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries (gwlbtun ${CMAKE_THREAD_LIBS_INIT})
