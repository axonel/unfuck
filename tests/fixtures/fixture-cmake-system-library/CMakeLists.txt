cmake_minimum_required(VERSION 3.10)
project(test-cmake-syslib C)
find_library(TEST_LIB nonexistent_native_lib REQUIRED)
