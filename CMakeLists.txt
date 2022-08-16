cmake_minimum_required(VERSION 3.18)
project(HPSI VERSION 1.0)
add_executable(HPSI main.cpp)

set(CMAKE_CXX_FLAGS "-Wall -Werror")
set(CMAKE_CXX_STANDARD 11)

find_package(SEAL REQUIRED)
target_link_libraries(HPSI SEAL::seal)