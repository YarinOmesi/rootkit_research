cmake_minimum_required(VERSION 3.28)

project(yarin_module LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D__KERNEL__ -DMODULE)

execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Find the headers
find_path(
        KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /usr/src/linux-headers-${KERNEL_RELEASE}
)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")
message(STATUS "Source Dir ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Binary Dir ${CMAKE_CURRENT_BINARY_DIR}")


include_directories(
        ${KERNELHEADERS_DIR}/include
        ${KERNELHEADERS_DIR}/arch/x86/include
)

add_library(dummy_target yarin_module.c)
