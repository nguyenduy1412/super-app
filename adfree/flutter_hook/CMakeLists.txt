cmake_minimum_required(VERSION 3.22.1)
project(flutter_hook CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(flutter_hook SHARED
    flutter_hook.cpp
)

target_link_libraries(flutter_hook
    log
    z
)
