cmake_minimum_required(VERSION 3.10)
project(network C)

set(CMAKE_C_STANDARD 99)
set(INC_DIR "E:/CLion 2018.1.5/plugins/WpdPack/Include")
set(LINK_DIR "E:/CLion 2018.1.5/plugins/WpdPack/Lib")

include_directories(${INC_DIR})
link_directories(${LINK_DIR})
link_libraries(wpcap Packet)

add_executable(network main.c protocal.h)
target_link_libraries(network wpcap Packet)