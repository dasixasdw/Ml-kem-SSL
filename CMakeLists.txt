cmake_minimum_required(VERSION 3.21)
project(MyProject)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(liboqs REQUIRED)

add_executable(MLkem main.cpp)


target_link_libraries(MLkem PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        OQS::oqs
)
