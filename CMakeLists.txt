cmake_minimum_required(VERSION 3.21)
project(MyProject)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===================== 新增：完整中文适配核心配置 开始 =====================
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

# 4. Linux/MacOS 下UTF-8是系统默认编码，无需额外配置，天然兼容中文
# ===================== 新增：完整中文适配核心配置 结束 =====================

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(liboqs REQUIRED)

add_executable(MLkem main.cpp)

target_link_libraries(MLkem PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        OQS::oqs
)