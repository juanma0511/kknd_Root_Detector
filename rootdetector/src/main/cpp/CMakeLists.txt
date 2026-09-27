cmake_minimum_required(VERSION 3.22.1)
project("rootdetector")

add_library(rootdetector SHARED
    native_root_checks.cpp
)

target_link_libraries(rootdetector
    android
    log
)

target_compile_options(rootdetector PRIVATE
    -std=c++17
    -fvisibility=hidden
    -fstack-protector-all
    -O2
)

target_link_options(rootdetector PRIVATE
    -Wl,-z,max-page-size=16384
)
