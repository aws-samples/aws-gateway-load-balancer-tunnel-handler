cmake_minimum_required(VERSION 3.13)
project(gwlbtun)
set(CMAKE_CXX_STANDARD 17)
find_package(Threads)

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

add_executable(gwlbtun main.cpp UDPPacketReceiver.cpp UDPPacketReceiver.h GenevePacket.cpp GenevePacket.h TunInterface.cpp TunInterface.h utils.cpp utils.h PacketHeaderV4.cpp PacketHeaderV4.h PacketHeaderV6.cpp PacketHeaderV6.h GeneveHandler.cpp GeneveHandler.h FlowCache.h Logger.cpp Logger.h Logger.cpp)
target_link_libraries (gwlbtun ${CMAKE_THREAD_LIBS_INIT})
