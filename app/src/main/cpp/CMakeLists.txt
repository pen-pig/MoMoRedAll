cmake_minimum_required(VERSION 3.18.1)
project("plthook")

add_library(plthook SHARED plthook.cpp)

target_compile_features(plthook PRIVATE cxx_std_17)

target_link_libraries(plthook
    android
    log
    dl
)
