cmake_minimum_required(VERSION 3.21)
project(MLkem)  # 项目名和你的一致
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ====================== ✅ 中文编码完美适配 (解决MinGW中文乱码) ======================
if(MSVC OR MINGW)
    add_compile_options(-finput-charset=utf-8 -fexec-charset=utf-8)
    add_definitions(-DUNICODE -D_UNICODE)
endif()

# ====================== ✅ 跨平台编译宏 (适配Windows/Linux) ======================
if (WIN32)
    add_definitions(-D_WIN32 -DWIN32 -D_WINSOCK_DEPRECATED_NO_WARNINGS)
    # MinGW下的Socket库链接
    link_libraries(ws2_32 wsock32)
endif ()

if (UNIX AND NOT APPLE)
    add_compile_options(-Wall -Wextra -O2)
    link_libraries(pthread m)
endif ()

# ====================== ✅ 依赖库配置 (完全贴合你的vcpkg日志建议) ======================
# OpenSSL 3.6.0 (你的vcpkg安装版本)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
# liboqs (你的vcpkg安装版本 0.15.0)
find_package(liboqs CONFIG REQUIRED)

# ====================== ✅ 所有源文件列表 (核对你的文件，一个都不能少) ======================
set(ALL_SOURCE_FILES
        main.cpp
        crypto_utils.cpp
        socket_utils.cpp
        kem_server.cpp
        kem_client.cpp
)

# ====================== ✅ 编译目标名改为 MLkem (核心修复！解决unknown target) ======================
add_executable(MLkem ${ALL_SOURCE_FILES})

# ====================== ✅ 链接依赖库 (你的vcpkg日志里的标准写法) ======================
target_link_libraries(MLkem PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        OQS::oqs
)

# ====================== ✅ Windows自动复制DLL (运行时不报错，必须加) ======================
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