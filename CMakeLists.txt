cmake_minimum_required(VERSION 3.10)
project(network C)

set(CMAKE_C_STANDARD 99)
set(INC_DIR "./include")
set(LINK_DIR "./lib")

include_directories(${INC_DIR})
link_directories(${LINK_DIR})
link_libraries(wpcap Packet wsock32 pthreadVC2 pthreadVCE2 pthreadVSE2)

add_executable(network protocol.h catch_packet.c pcap_analysis.c pcap_analysis.h)
target_link_libraries(network wpcap Packet pthreadVC2 pthreadVCE2 pthreadVSE2 wsock32)