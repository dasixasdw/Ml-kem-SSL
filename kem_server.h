/**
 * @file kem_server.h
 * @brief ML-KEM Post Quantum Cryptography Project - Multi-algorithm KEM Server Header File
 * @brief ML-KEM抗量子密码学项目 - 多算法KEM服务端头文件
 * @details Declare the MultiAlgKemServer core class and its public interface, encapsulate post-quantum server core attributes and business methods, support ML-KEM series algorithm negotiation, TLS1.3 encrypted communication and cross-platform socket listening.
 * @details 声明多算法抗量子服务端核心类及对外接口，封装服务端核心属性与业务方法，支持ML-KEM系列算法协商、TLS1.3加密通信及跨平台套接字监听能力。
 * @date 2026/01/19
 */

#ifndef MLKEM_KEM_SERVER_H
#define MLKEM_KEM_SERVER_H

#include "common.h"
#include <string>
#include <unordered_map>
#include <openssl/ssl.h>
#include <oqs/oqs.h>

/**
 * @brief Global external declaration of server supported post-quantum algorithm list
 * 服务端支持的抗量子算法列表 - 全局外部声明
 * @details Only include ML-KEM series standard algorithms (512/768/1024), remove NTRU algorithm, unified algorithm parameter configuration
 * @details 仅包含ML-KEM系列标准抗量子算法，移除NTRU算法，统一定义各算法的密钥/密文长度参数
 */
extern const std::unordered_map<std::string, KemAlgInfo> SUPPORTED_ALGS;

/**
 * @brief Multi-algorithm compatible post-quantum KEM server core class
 * 多算法兼容式 抗量子KEM服务端核心类
 * @details Integrate cross-platform socket listening, application layer algorithm negotiation, liboqs ML-KEM key exchange, OpenSSL TLS1.3 encrypted communication, realize safe encrypted communication based on post-quantum cryptography
 * @details 集成跨平台套接字监听、应用层算法协商、liboqs ML-KEM密钥交换、OpenSSL TLS1.3加密通信，实现基于抗量子密码的安全加密通信
 */
class MultiAlgKemServer
{
private:
    // ✅ Member variable order strictly matches the initialization list in cpp file, eliminate compilation warnings
    // ✅ 成员变量声明顺序 严格匹配cpp初始化列表，消除编译警告，无任何语法告警
    SOCKET_FD m_srv_fd;        // Server listening socket file descriptor | 服务端监听套接字文件描述符
    SSL_CTX* m_ssl_ctx;        // Server SSL/TLS encryption context pointer | 服务端SSL/TLS加密上下文指针
    std::string m_cert_path;   // File path of TLS certificate (PEM format) | TLS证书文件路径（PEM格式）
    std::string m_key_path;    // File path of TLS private key (PEM format) | TLS私钥文件路径（PEM格式）

public:
    /**
     * @brief Constructor of MultiAlgKemServer class
     * 多算法抗量子服务端类的构造函数
     * @param cert_path File path of TLS certificate in PEM format
     *        PEM格式的TLS证书文件路径
     * @param key_path File path of TLS private key in PEM format
     *        PEM格式的TLS私钥文件路径
     * @note Use explicit keyword to avoid implicit type conversion, improve code security
     * @note 显式声明explicit关键字，杜绝隐式类型转换，提升代码安全性
     */
    explicit MultiAlgKemServer(const std::string& cert_path, const std::string& key_path);

    /**
     * @brief Destructor of MultiAlgKemServer class
     * 多算法抗量子服务端类的析构函数
     * @details Release all allocated system resources, including listening socket, SSL context and crypto library resources, prevent memory leak
     * @details 释放所有已分配的系统资源，包含监听套接字、SSL上下文及密码学库资源，杜绝内存泄漏与句柄占用
     */
    ~MultiAlgKemServer();

    /**
     * @brief Server core business startup method
     * 服务端核心业务启动方法
     * @details Start permanent socket listening, process client connection requests in a loop, complete algorithm negotiation, key exchange, TLS handshake and encrypted communication
     * @details 启动套接字永久监听，循环处理客户端连接请求，完成算法协商、密钥交换、TLS握手及加密通信全流程
     */
    void startServer();
};

#endif // MLKEM_KEM_SERVER_H