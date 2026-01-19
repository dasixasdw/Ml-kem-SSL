cmake_minimum_required(VERSION 3.21)
project(MyProject)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. 强制源文件编码为 UTF-8 (全局生效，解决中文编译乱码核心)
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/source-charset:utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")

# 2. MSVC编译器专属：指定程序运行时的字符集为UTF-8，彻底解决运行时中文输出乱码
if(MSVC)
    add_compile_options("/utf-8")
    add_definitions(-D_UNICODE -DUNICODE)
endif()

# 3. MinGW编译器(Windows下) 中文编码适配
if(MINGW)
    add_compile_options(-finput-charset=utf-8 -fexec-charset=utf-8)
endif()


# 1. Windows平台通用宏定义 (MSVC/MinGW都生效)，兼容你的跨平台代码里的#ifdef _WIN32
if (WIN32)
    add_definitions(-D_WIN32 -DWIN32 -D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif ()

# 2. Linux平台通用宏定义，兼容代码里的Linux逻辑
if (UNIX AND NOT APPLE)
    add_compile_options(-Wall -Wextra -O2)
endif ()

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(liboqs REQUIRED CONFIG)

add_executable(MLkem main.cpp)

target_link_libraries(MLkem PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        OQS::oqs
        $<$<PLATFORM_ID:Windows>:ws2_32>
        $<$<PLATFORM_ID:Windows>:wsock32>
        $<$<PLATFORM_ID:Linux>:pthread>
        $<$<PLATFORM_ID:Linux>:m>
)

if (WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(TARGET MLkem POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:OpenSSL::Crypto> $<TARGET_FILE_DIR:MLkem>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:OpenSSL::SSL> $<TARGET_FILE_DIR:MLkem>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:OQS::oqs> $<TARGET_FILE_DIR:MLkem>
    )
endif ()