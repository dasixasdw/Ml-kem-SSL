#
# @brief ML-KEM抗量子密码项目 CMake 跨平台编译配置文件
# @brief ML-KEM Post Quantum Cryptography Project - CMake Cross-Platform Build Configuration
# @details 全平台编译适配：Windows(MinGW/MSVC) + WSL/Ubuntu/Linux，兼容CLion内置vcpkg包管理，整合OpenSSL+liboqs依赖编译逻辑
# @details Cross-platform build support: Windows(MinGW/MSVC) + WSL/Ubuntu/Linux, compatible with CLion built-in vcpkg, integrate OpenSSL&liboqs dependency build logic
# @details 核心修复点：解决跨平台证书拷贝语法兼容问题、Linux文件权限问题、OpenSSL3.6.0安全策略适配、双编译器中文乱码问题
# @details Core Fixes: resolve cross-platform cert copy syntax compatibility, Linux file permission issue, OpenSSL3.6.0 security policy adaption, double compiler Chinese garbled code
# @date 2026/01/20
#
cmake_minimum_required(VERSION 3.21)
project(cmake-build-debug-wsl/MLkem)

# Set global C++ standard: force C++20 standard, disable extended grammar, compatible with all compilers | 设置全局C++标准：强制C++20标准，关闭扩展语法，全编译器通用
set(CMAKE_CXX_STANDARD 20)
# Enable C++ standard mandatory check: ensure compiler strictly follow C++20 specification | 开启C++标准强制校验：保证编译器严格遵循C++20规范
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compatible with CLion build profile: do not force build mode, auto follow Debug/Release selection | 兼容CLion编译配置：不强制指定编译模式，自动跟随Debug/Release配置项选择
# set(CMAKE_BUILD_TYPE Release)

# Core vcpkg configuration: force use CLion built-in vcpkg toolchain, auto adapt Win32/WSL environment | 核心vcpkg配置：强制调用CLion内置vcpkg工具链，自动适配Win32/WSL全环境
# Note: do not modify this path, it's the default built-in vcpkg path of CLion | 注：不可修改此路径，为CLion默认内置vcpkg路径
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/.vcpkg-clion/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# ====================== ✅ Cross-platform: Encoding Format + Compilation Warning Adaptive Configuration | 全平台 编码格式 + 编译警告 差异化适配 ======================
# Windows-MinGW: solve Chinese garbled code with UTF-8 encoding, close deprecated API warning | Windows-MinGW：UTF8编码彻底解决中文乱码，关闭废弃API声明警告
if(MINGW)
add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8 -Wall -Wno-deprecated-declarations)
add_definitions(-DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601)
# Windows-MSVC: cure Chinese garbled code with UTF-8 encoding, shield unsafe function warning | Windows-MSVC：UTF8编码根治中文乱码，屏蔽不安全函数/中文编码警告
elseif(MSVC)
add_compile_options(/utf-8 /wd4996 /wd4819 /W3)
add_definitions(-DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0601)
# Linux/WSL: compile optimization + position-independent code, define Linux platform macro for business code | Linux/WSL：编译优化+位置无关代码，定义Linux平台宏供业务代码判断
elseif(UNIX AND NOT APPLE)
add_compile_options(-Wall -O2 -fPIC)
add_definitions(-D_LINUX)
endif()

# ====================== ✅ Cross-platform: System Macro + Dependent Link Library Adaptive Configuration | 全平台 系统宏定义 + 依赖链接库 差异化适配 ======================
if (WIN32)
# Windows common macro: mark Win32 platform, shield Socket deprecated API warning | Windows通用宏：标识Win32平台，屏蔽Socket旧API废弃警告
add_definitions(-D_WIN32 -DWIN32 -D_WINSOCK_DEPRECATED_NO_WARNINGS)
# MinGW exclusive: must link Windows Socket library, otherwise network function link failure | MinGW专属：必须链接Windows Socket库，否则网络相关函数链接失败
if(MINGW)
link_libraries(ws2_32 wsock32)
# MSVC exclusive: static link runtime library, no VS runtime dependency for distribution | MSVC专属：静态链接运行时库，打包程序无VS运行时依赖，可直接分发运行
elseif(MSVC)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
# Linux/WSL exclusive: must link system dependent libraries, required by openssl/liboqs runtime | Linux/WSL专属：必须链接的系统依赖库，openssl/liboqs运行强制依赖，缺一不可
elseif(UNIX AND NOT APPLE)
link_libraries(pthread m dl)
endif ()

# ====================== ✅ Third-party Dependent Library Auto Load Configuration | 第三方依赖库 自动加载配置 ======================
# Auto load OpenSSL crypto library via vcpkg, compatible with all platforms | 通过vcpkg自动加载OpenSSL密码学库，全平台兼容无路径配置
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
# Auto load liboqs post-quantum crypto library via vcpkg, follow official CMake config | 通过vcpkg自动加载liboqs抗量子密码库，遵循官方CMake配置规范
find_package(liboqs CONFIG REQUIRED)

# ====================== ✅ Project Source File List | 项目源文件列表 ======================
set(ALL_SOURCE_FILES
main.cpp
crypto_utils.cpp
socket_utils.cpp
kem_server.cpp
kem_client.cpp
)

# Generate executable file: bind all source files to build target MLkem | 生成可执行文件：绑定所有源文件至编译目标MLkem
add_executable(MLkem ${ALL_SOURCE_FILES})

# Link dependent libraries in private mode: avoid dependency pollution, standard CMake linking | 私有模式链接依赖库：避免依赖污染，CMake标准化链接方式
target_link_libraries(MLkem PRIVATE
OpenSSL::Crypto
OpenSSL::SSL
OQS::oqs
)

# ====================== ✅ Core Fix: Cross-platform Certificate File Auto Copy [No Syntax Error] | 核心修复 全平台证书文件自动拷贝 【无语法错误/跨平台兼容】 ======================
# Post-build event: create cert directory and copy certificate files to executable directory automatically | 编译后事件：自动在程序运行目录创建cert目录+拷贝证书文件
# Solve problem: certificate load failure caused by inconsistent path, ensure certificate file always exists | 解决问题：证书路径不一致导致的加载失败/文件缺失错误，保证证书永不丢失
# Core feature: copy_if_different only copy updated certificate, no redundant copy, improve build efficiency | 核心特性：仅拷贝更新后的证书文件，不重复拷贝，提升编译效率
add_custom_command(TARGET MLkem POST_BUILD
COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:MLkem>/cert
COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/cert/cert.pem $<TARGET_FILE_DIR:MLkem>/cert/cert.pem
COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/cert/key.pem $<TARGET_FILE_DIR:MLkem>/cert/key.pem
)

# ====================== ✅ Linux/WSL Exclusive: Certificate File Permission Fix [Independent Isolation] | Linux/WSL专属 证书文件权限修复 【独立隔离 不影响Windows】 ======================
# Note: use CMake IF condition judgment, Windows platform will skip this block completely | 注：采用CMake条件判断，Windows平台将完全跳过此代码块，无任何解析错误
# Solve problem: Linux file permission denied when loading certificate, set standard readable permission | 解决问题：Linux加载证书时的文件权限拒绝错误，设置标准可读权限
if(UNIX AND NOT APPLE)
add_custom_command(TARGET MLkem POST_BUILD
COMMAND chmod 755 $<TARGET_FILE_DIR:MLkem>/cert
COMMAND chmod 644 $<TARGET_FILE_DIR:MLkem>/cert/cert.pem
COMMAND chmod 644 $<TARGET_FILE_DIR:MLkem>/cert/key.pem
)
endif()

# ====================== ✅ Windows Exclusive: Dependent DLL Auto Copy [No Impact on Linux] | Windows专属 依赖DLL自动拷贝 【无任何Linux环境影响】 ======================
# Valid only on Windows platform: copy dynamic link library to executable directory automatically | 仅在Windows平台生效：自动拷贝动态链接库至程序运行目录
# Solve problem: program crash caused by missing DLL, no need to manually copy dependency files | 解决问题：缺失DLL导致的程序运行闪退，无需手动拷贝依赖文件
if (WIN32 AND BUILD_SHARED_LIBS)
add_custom_command(TARGET MLkem POST_BUILD
COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:OpenSSL::Crypto> $<TARGET_FILE_DIR:MLkem>
COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:OpenSSL::SSL> $<TARGET_FILE_DIR:MLkem>
COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:OQS::oqs> $<TARGET_FILE_DIR:MLkem>
)
endif ()