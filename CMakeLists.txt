cmake_minimum_required(VERSION 3.13)
project(gwlbtun)
set(CMAKE_CXX_STANDARD 17)
find_package(Threads)

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")

set(CMAKE_CXX_FLAGS_DEBUG "-fstack-protector-all -fsanitize=address -pg -O0")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-lasan")

add_compile_options("")
# Debug or testing options.
#add_compile_options("-fstack-protector-all")
# add_compile_options("-fsanitize=address")
# add_link_options("-lasan")

add_executable(gwlbtun main.cpp UDPPacketReceiver.cpp UDPPacketReceiver.h GenevePacket.cpp GenevePacket.h TunInterface.cpp TunInterface.h utils.cpp utils.h PacketHeaderV4.cpp PacketHeaderV4.h PacketHeaderV6.cpp PacketHeaderV6.h GeneveHandler.cpp GeneveHandler.h)
target_link_libraries (gwlbtun ${CMAKE_THREAD_LIBS_INIT})
