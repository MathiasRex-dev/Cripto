cmake_minimum_required(VERSION 3.20)
project(CipherModule CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(GTest REQUIRED)

add_definitions(-DWITH_OPENSSL)

add_library(cipher_engine INTERFACE)
target_include_directories(cipher_engine INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cipher_engine INTERFACE OpenSSL::Crypto nlohmann_json::nlohmann_json)

enable_testing()
add_executable(unit_tests tests.cpp)
target_link_libraries(unit_tests PRIVATE cipher_engine GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(unit_tests)
