/**
* @file common.h
 * @brief ML-KEM Post Quantum Cryptography Project - Public Common Header File
 * @brief ML-KEM抗量子密码学项目 公共通用头文件
 * @details Unified cross-platform compilation configuration, global constant definition, data structure declaration and public macro definition for the whole project.
 * @details 为本项目提供统一的跨平台编译配置、全局常量定义、核心数据结构声明及公共宏定义，是项目的基础公共依赖头文件。
 * @date 2026/01/19
 */

#ifndef MLKEM_COMMON_H
#define MLKEM_COMMON_H

#include <string>
#include <unordered_map>
#include <cstddef>

/**
 * @brief Cross-platform compilation macro definition, compatible with Windows and Linux/WSL dual environment
 * 跨平台编译宏定义模块 - 兼容Windows、Linux/WSL双编译运行环境
 * @details Unified socket related data types and function calls, solve the system-dependent socket API differences
 * 统一Socket相关数据类型与函数调用，解决Socket接口的系统差异性问题
 */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define SOCKET_FD         SOCKET                  // Socket file descriptor type on Windows  Windows平台的套接字文件描述符类型
#define CLOSE_SOCKET(fd)  closesocket(fd)         // Socket close function on Windows        Windows平台的套接字关闭函数
#define IS_INVALID_FD(fd) (fd == INVALID_SOCKET)  // Judge invalid socket on Windows         Windows平台的无效套接字判断条件
#define SOCKET_REUSE_FLAG SO_REUSEADDR            // Socket port reuse flag on Windows       Windows平台的端口复用标识
#define CERT_FILE "C:/Users/22126/CLionProjects/MLkem/server.crt"  // TLS certificate file path  TLS证书文件路径
#define KEY_FILE  "C:/Users/22126/CLionProjects/MLkem/server.key"   // TLS private key file path  TLS私钥文件路径
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#define SOCKET_FD         int                     // Socket file descriptor type on Linux    Linux平台的套接字文件描述符类型
#define CLOSE_SOCKET(fd)  close(fd)               // Socket close function on Linux          Linux平台的套接字关闭函数
#define INVALID_SOCKET    -1                      // Invalid socket value definition on Linux Linux平台的无效套接字值定义
#define IS_INVALID_FD(fd) (fd == -1)              // Judge invalid socket on Linux           Linux平台的无效套接字判断条件
#define SOCKET_REUSE_FLAG (SO_REUSEADDR | SO_REUSEPORT)  // Socket port reuse flag on Linux Linux端口复用标识(地址+端口)
#define CERT_FILE "./cert/cert.pem" // TLS certificate path on WSL WSL环境TLS证书路径
#define KEY_FILE  "./cert/key.pem"   // TLS private key path on WSL WSL环境TLS私钥路径
#endif

/**
 * @brief Global constant definition module, unified configuration center for the whole project
 * 全局常量定义模块 - 项目统一配置中心
 * @details All hard-coded constant parameters are centrally managed here, modify once to take effect globally, no need to modify other files
 * 所有硬编码常量参数集中在此处管理，一改全改全局生效，无需修改项目其他文件，降低维护成本
 */
constexpr size_t SHARED_SECRET_LEN = 32;    // The fixed length of shared secret for all KEM algorithms in liboqs, follow the official standard | liboqs库所有KEM算法的共享密钥固定长度，遵循官方标准规范
constexpr size_t MAX_ALG_NAME_LEN = 64;     // Maximum length of KEM algorithm name, prevent buffer overflow | 抗量子算法名称的最大长度，防止缓冲区溢出安全问题
constexpr int SERVER_PORT = 8888;           // The listening port number of the ML-KEM server | ML-KEM服务端监听端口号
constexpr const char* SERVER_IP = "127.0.0.1";  // The bound IP address of the ML-KEM server, use local loopback address | ML-KEM服务端绑定的IP地址，使用本地回环地址

/**
 * @brief KEM algorithm information structure definition
 * 抗量子密钥封装机制(KEM)算法信息结构体定义
 * @details Store the core attribute information of the post-quantum KEM algorithm, including name and key length parameters
 * 存储后量子时代KEM算法的核心属性信息，包含算法名称及各类密钥/密文的长度参数
 */
struct KemAlgInfo {
    std::string alg_name;  // Name of the post-quantum KEM algorithm | 后量子KEM算法的标准名称
    size_t pk_len;         // Length of the public key for the corresponding algorithm (unit: byte) | 对应算法的公钥长度，单位：字节
    size_t sk_len;         // Length of the private key for the corresponding algorithm (unit: byte) | 对应算法的私钥长度，单位：字节
    size_t ct_len;         // Length of the ciphertext for the corresponding algorithm (unit: byte) | 对应算法的密文长度，单位：字节
};

/**
 * @brief Global external declaration of supported algorithm list
 * 服务端支持的后量子算法列表 - 全局外部声明
 * @details Reusable read-only mapping table, the key is the algorithm name, the value is the corresponding algorithm attribute information
 * 可复用的只读映射表，键为算法名称，值为对应的算法属性信息，全局一处定义、多处引用
 */
extern const std::unordered_map<std::string, KemAlgInfo> SUPPORTED_ALGS;

#endif // MLKEM_COMMON_H