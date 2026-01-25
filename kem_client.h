/**
 * @file kem_client.h
 * @brief ML-KEM Post Quantum Cryptography Project - Multi-algorithm Switchable KEM Client Header File
 * @brief ML-KEM抗量子密码学项目 - 多算法可切换式KEM客户端头文件
 * @details Declare the SwitchableKemClient class and its public interface, encapsulate post-quantum client core attributes and business methods, support multi-algorithm dynamic switching and TLS1.3 encrypted communication.
 * @details 声明可切换算法KEM客户端类及对外接口，封装抗量子客户端核心属性与业务方法，支持多算法动态切换与TLS1.3加密通信能力。
 * @date 2026/01/19
 */

#ifndef MLKEM_KEM_CLIENT_H
#define MLKEM_KEM_CLIENT_H

#include "common.h"
#include <openssl/ssl.h>
#include <string>

/**
 * @brief Multi-algorithm switchable post-quantum KEM client core class
 * 多算法可切换式 抗量子KEM客户端核心类
 * @details Integrate cross-platform socket communication, liboqs post-quantum key exchange, OpenSSL TLS1.3 encrypted communication, support dynamic switch of ML-KEM/NTRU series algorithms
 * @details 集成跨平台套接字通信、liboqs抗量子密钥协商、OpenSSL TLS1.3加密通信能力，支持ML-KEM/NTRU系列算法动态切换
 */
class SwitchableKemClient {
private:
    SOCKET_FD m_cli_fd;        // Client socket file descriptor | 客户端套接字文件描述符
    SSL_CTX* m_ssl_ctx;        // Client SSL/TLS encryption context pointer | 客户端SSL/TLS加密上下文指针
    std::string m_srv_ip;      // Target server IP address | 目标服务器的IP地址
    int m_srv_port;            // Target server listening port | 目标服务器的监听端口号
    std::string m_alg_name;    // Selected post-quantum KEM algorithm name | 选定的抗量子KEM算法名称

public:
    /**
     * @brief Constructor of SwitchableKemClient
     * 客户端类构造函数
     * @param ip Target server IP address to connect
     *        待连接的目标服务器IP地址
     * @param port Target server listening port number
     *        待连接的目标服务器监听端口号
     * @param alg_name Selected post-quantum KEM algorithm name, default ML-KEM-768
     *        选定的抗量子KEM算法名称，默认值为ML-KEM-768（主流标准算法）
     * @details Core optimization: add default algorithm parameter, compatible with parameter-free calling mode
     * @details 核心优化：为算法参数增加默认值，兼容无参调用方式，提升开发便捷性
     */
    SwitchableKemClient(const std::string& ip, int port, const std::string& alg_name = "ML-KEM-768");

    /**
     * @brief Destructor of SwitchableKemClient
     * 客户端类析构函数
     * @details Release all allocated resources, including SSL context, socket resources and crypto library resources, prevent memory leak
     * @details 释放所有已分配的资源，包含SSL上下文、套接字资源及密码学库资源，杜绝内存泄漏
     */
    ~SwitchableKemClient();

    /**
     * @brief Client core business method
     * 客户端核心业务处理方法
     * @details Complete the whole process: create client socket -> connect to server -> algorithm negotiation -> post-quantum KEM key exchange -> TLS1.3 handshake -> encrypted data transmission
     * @details 完成客户端全业务流程：创建套接字 → 连接服务器 → 算法协商 → 抗量子KEM密钥交换 → TLS1.3握手 → 加密数据收发
     */
    void connectAndCommunicate();
};

#endif // MLKEM_KEM_CLIENT_H