cmake_minimum_required(VERSION 3.14)
project(probe_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(test_openssl3_cert_load test_openssl3_cert_load.cpp)

target_link_libraries(test_openssl3_cert_load PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(test_openssl3_cert_load PRIVATE -Wall -Wextra)
