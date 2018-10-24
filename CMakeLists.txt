cmake_minimum_required(VERSION 3.12)
project(ISA)

set(CMAKE_CXX_STANDARD 14)

add_executable(ISA dns-export.cpp headers/dns-export.h headers/pcap-parse.h pcap-parse.cpp)