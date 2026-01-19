//
// Created by 22126 on 2026/1/19.
//

#ifndef MLKEM_COMMON_H
#define MLKEM_COMMON_H

#include <string>
#include <unordered_map>
#include <cstddef>

// ====================== ✅ 完美跨平台编译宏【Windows + Linux/WSL 双环境兼容】 ======================
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define SOCKET_FD         SOCKET
#define CLOSE_SOCKET(fd)  closesocket(fd)
#define IS_INVALID_FD(fd) (fd == INVALID_SOCKET)
#define SOCKET_REUSE_FLAG SO_REUSEADDR
// ✅ 修复：改为const char* 字符串，兼容std::string传参，解决转换失败
#define CERT_FILE "C:/Users/22126/CLionProjects/MLkem/server.crt"
#define KEY_FILE  "C:/Users/22126/CLionProjects/MLkem/server.key"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#define SOCKET_FD         int
#define CLOSE_SOCKET(fd)  close(fd)
#define INVALID_SOCKET    -1          // ✅ Linux/WSL 下无效Socket值为 -1
#define IS_INVALID_FD(fd) (fd == -1)
#define SOCKET_REUSE_FLAG (SO_REUSEADDR | SO_REUSEPORT)
// ✅ 修复：改为const char* 字符串，兼容std::string传参，解决转换失败
#define CERT_FILE "/mnt/c/Users/22126/CLionProjects/MLkem/cmake-build-debug-wsl/server.crt"
#define KEY_FILE  "/mnt/c/Users/22126/CLionProjects/MLkem/cmake-build-debug-wsl/server.key"
#endif

// ====================== ✅ 全局常量【一改全改，无需改其他文件】 ======================
constexpr size_t SHARED_SECRET_LEN = 32;    // liboqs所有KEM算法 共享密钥固定32字节(官方标准)
constexpr size_t MAX_ALG_NAME_LEN = 64;     // 算法名最大长度，防缓冲区溢出
constexpr int SERVER_PORT = 8888;           // 监听端口
constexpr const char* SERVER_IP = "127.0.0.1"; // ✅ 修复：改为const char*，兼容std::string传参

// ====================== ✅ 抗量子算法信息结构体 ======================
struct KemAlgInfo {
    std::string alg_name;
    size_t pk_len;  // 公钥长度
    size_t sk_len;  // 私钥长度
    size_t ct_len;  // 密文长度
};

// ====================== ✅ 【服务器支持的算法列表】全局声明，复用即可 ======================
extern const std::unordered_map<std::string, KemAlgInfo> SUPPORTED_ALGS;

#endif // MLKEM_COMMON_H