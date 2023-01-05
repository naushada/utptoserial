cmake_minimum_required(VERSION 3.16.3)
project(udp-serial)


#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a -g -Wall -Wextra")

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "*.cpp")

add_executable(udpserial ${SOURCES})


install(TARGETS udpserial
	CONFIGURATIONS Release
        RUNTIME DESTINATION /usr/bin
)

