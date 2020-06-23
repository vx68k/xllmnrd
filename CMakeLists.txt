cmake_minimum_required(VERSION 3.10)

project(xllmnrd VERSION 4.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(cmakeconfig.h.in config.h)

add_subdirectory(libxllmnrd)
add_subdirectory(xllmnrd)
