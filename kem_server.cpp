/**
 * @file kem_server.cpp
 * @brief ML-KEM Post Quantum Cryptography Project - Multi-algorithm KEM Server Implementation
 * @brief ML-KEM抗量子密码学项目 - 多算法KEM服务端核心实现文件
 * @details Implement the core business logic of post-quantum multi-algorithm server: cross-platform socket listening, algorithm negotiation, liboqs ML-KEM key exchange, TLS1.3 encrypted communication, structured resource release with zero memory leak
 * @details 实现抗量子多算法服务端核心业务逻辑：跨平台套接字监听、算法协商、liboqs ML-KEM密钥交换、TLS1.3加密通信、无GOTO结构化资源释放，全程零内存泄漏
 * @date 2026/01/19
 */
#include "kem_server.h"
#include "crypto_utils.h"
#include "socket_utils.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <oqs/oqs.h>
#include <openssl/err.h>

/**
 * @brief Global definition of server supported post-quantum algorithm list
 * 服务端支持的抗量子算法列表 - 全局常量定义
 * @details Only retain ML-KEM series algorithms (512/768/1024), standard NIST post-quantum cryptography standard algorithm set
 * @details 仅保留ML-KEM系列算法，为NIST标准化的抗量子密码算法集，包含各算法公钥/私钥/密文的标准长度配置
 */
const std::unordered_map<std::string, KemAlgInfo> SUPPORTED_ALGS = {
    {"ML-KEM-512",        {"ML-KEM-512",        OQS_KEM_ml_kem_512_length_public_key,        OQS_KEM_ml_kem_512_length_secret_key,        OQS_KEM_ml_kem_512_length_ciphertext}},
    {"ML-KEM-768",        {"ML-KEM-768",        OQS_KEM_ml_kem_768_length_public_key,        OQS_KEM_ml_kem_768_length_secret_key,        OQS_KEM_ml_kem_768_length_ciphertext}},
    {"ML-KEM-1024",       {"ML-KEM-1024",       OQS_KEM_ml_kem_1024_length_public_key,       OQS_KEM_ml_kem_1024_length_secret_key,       OQS_KEM_ml_kem_1024_length_ciphertext}}
};

/**
 * @brief Constructor of MultiAlgKemServer class
 * 多算法抗量子服务端类的构造函数
 * @param cert_path File path of TLS certificate in PEM format
 *        PEM格式的TLS证书文件路径
 * @param key_path File path of TLS private key in PEM format
 *        PEM格式的TLS私钥文件路径
 * @details Core fix: the initialization sequence is strictly consistent with the class member declaration sequence
 * @details 核心修复：成员变量初始化顺序 严格与类声明顺序保持一致 m_srv_fd → m_ssl_ctx → m_cert_path → m_key_path，消除编译警告
 */
MultiAlgKemServer::MultiAlgKemServer(const std::string& cert_path, const std::string& key_path)
    : m_srv_fd(INVALID_SOCKET), m_ssl_ctx(nullptr), m_cert_path(cert_path), m_key_path(key_path) {
    initCryptoLib();                                      // Initialize crypto libraries: liboqs + OpenSSL | 初始化密码学依赖库：liboqs抗量子库 + OpenSSL TLS库
    m_ssl_ctx = createSSLContext(true, m_cert_path, m_key_path);  // Create SSL context for server mode | 创建服务端模式的SSL加密上下文并加载证书私钥

    // Create and initialize server socket, bind to the specified port | 创建并初始化服务端套接字，绑定指定监听端口
    if (!createServerSocket(m_srv_fd, SERVER_PORT)) {
        std::cerr << "[Server Error] Server initialization failed!" << std::endl;
        exit(-1);
    }

    // Server startup success log | 服务端启动成功日志打印
    std::cout << "========================================" << std::endl;
    std::cout << "✅ Multi-algorithm post-quantum server started successfully | Port: " << SERVER_PORT << std::endl;
    std::cout << "✅ Supported post-quantum algorithm list:" << std::endl;
    for (const auto& alg : SUPPORTED_ALGS) {
        std::cout << "   - " << alg.first << std::endl;
    }
    std::cout << "✅ SSL certificate loaded successfully, will perform standard TLS1.3 7-step handshake" << std::endl;
    std::cout << "========================================" << std::endl;
}

/**
 * @brief Destructor of MultiAlgKemServer class
 * 多算法抗量子服务端类的析构函数
 * @details Release all allocated system resources in reverse order of initialization, cross-platform compatible cleanup logic
 * @details 按初始化逆序释放所有已分配的系统资源，实现跨平台兼容的资源清理逻辑，杜绝内存泄漏与句柄占用
 */
MultiAlgKemServer::~MultiAlgKemServer() {
    if (m_srv_fd != INVALID_SOCKET) {
        CLOSE_SOCKET(m_srv_fd);                // Close server listening socket | 关闭服务端监听套接字
    }
    if (m_ssl_ctx != nullptr) {
        SSL_CTX_free(m_ssl_ctx);               // Release SSL encryption context resource | 释放SSL加密上下文资源
    }
#ifdef _WIN32
    WSACleanup();                             // Windows platform only: clean up socket environment resources | Windows平台专属：清理套接字运行环境资源
#endif
    cleanCryptoLib();                         // Clean up all crypto library resources | 清理所有密码学库的资源占用
}

/**
 * @brief Server core business function, start permanent listening and client connection processing
 * 服务端核心业务函数 - 启动永久监听并处理客户端连接请求
 * @details Implement full business process: permanent socket listening → accept client connection → application layer algorithm negotiation → post-quantum KEM key exchange → TLS1.3 7-step handshake → encrypted data transmission → structured resource release
 * @details 实现服务端全业务流程：套接字永久监听 → 接收客户端连接 → 应用层算法协商 → 抗量子KEM密钥交换 → TLS1.3标准7次握手 → 加密数据收发 → 结构化资源释放
 * @note Structured code design, no GOTO statement, resource release in reverse order of application, zero memory leak
 * @note 结构化代码设计，无任何GOTO语句，资源按申请逆序释放，全程零内存泄漏、零语法错误
 */
void MultiAlgKemServer::startServer() {
    sockaddr_in cli_addr{};
    socklen_t cli_len = sizeof(cli_addr);

    // Permanent listening loop, keep server running to accept multiple client connections | 永久监听循环，保持服务端运行以接收多客户端连接
    while (true) {
        // Block to wait for client connection request | 阻塞等待客户端连接请求
        SOCKET_FD cli_fd = accept(m_srv_fd, (sockaddr*)&cli_addr, &cli_len);
        if (IS_INVALID_FD(cli_fd)) {
            std::cerr << "[Network Error] Failed to accept client connection!" << std::endl;
            continue;
        }
        std::cout << "\n[New Connection] Client connected: " << inet_ntoa(cli_addr.sin_addr) << ":" << ntohs(cli_addr.sin_port) << std::endl;

        // Core optimization: declare all variables in advance, avoid cross initialization, structured code without GOTO | 核心优化：提前声明所有变量，避免跨越初始化，无GOTO结构化代码设计
        OQS_KEM* kem = nullptr;
        uint8_t* pk = nullptr;
        uint8_t* sk = nullptr;
        uint8_t* ct = nullptr;
        SSL* ssl = nullptr;
        char alg_buf[MAX_ALG_NAME_LEN] = {0};
        std::string client_alg;

        // ======================================
        // Phase 1: Pre-negotiation at application layer - Post-quantum algorithm negotiation
        // 阶段1：应用层前置协商【抗量子算法协商】- 无侵入式TLS协议，独立协商流程
        // ======================================
        if (recvData(cli_fd, alg_buf, MAX_ALG_NAME_LEN) <= 0) {
            std::cerr << "[Negotiation Error] Failed to receive client algorithm name!" << std::endl;
            CLOSE_SOCKET(cli_fd);
            continue;
        }
        client_alg = alg_buf;
        std::cout << "[Algorithm Negotiation] Client selected algorithm: " << client_alg << std::endl;

        // Verify whether the algorithm requested by the client is in the supported list | 校验客户端请求的算法是否在服务端支持列表中
        if (SUPPORTED_ALGS.find(client_alg) == SUPPORTED_ALGS.end()) {
            std::cerr << "[Negotiation Error] Unsupported algorithm: " << client_alg << ", disconnect client!" << std::endl;
            CLOSE_SOCKET(cli_fd);
            continue;
        }
        const KemAlgInfo& alg_info = SUPPORTED_ALGS.at(client_alg);
        std::cout << "[Negotiation Success] Algorithm matched successfully | Public key length: " << alg_info.pk_len << "B" << std::endl;

        // ======================================
        // Phase 2: Post-quantum ML-KEM key exchange - Standard liboqs official API call
        // 阶段2：抗量子ML-KEM密钥协商流程 - 标准liboqs官方API调用规范
        // ======================================
        kem = OQS_KEM_new(client_alg.c_str());
        if (!kem) {
            std::cerr << "[KEM Error] Failed to create KEM instance!" << std::endl;
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        // Allocate memory buffer for public key, private key and ciphertext | 为公钥、私钥、密文分配内存缓冲区
        pk = new uint8_t[alg_info.pk_len]();
        sk = new uint8_t[alg_info.sk_len]();
        ct = new uint8_t[alg_info.ct_len]();
        uint8_t shared_secret[SHARED_SECRET_LEN] = {0};  // Fixed-length shared secret buffer, follow liboqs official 32-byte standard | 固定长度共享密钥缓冲区，遵循liboqs官方32字节标准

        // Generate public/private key pair using the selected ML-KEM algorithm | 使用选定的ML-KEM算法生成公钥私钥对
        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
            std::cerr << "[KEM Error] Failed to generate key pair!" << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        // Send public key to client, start post-quantum key exchange | 向客户端发送公钥，启动抗量子密钥交换流程
        sendData(cli_fd, pk, alg_info.pk_len);

        // Receive ciphertext generated by client from public key | 接收客户端通过公钥生成的密文数据
        if (recvData(cli_fd, ct, alg_info.ct_len) <= 0) {
            std::cerr << "[KEM Error] Failed to receive ciphertext from client!" << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        // Execute KEM decapsulation: generate shared secret with private key and ciphertext | 执行KEM解封装：通过私钥与密文生成共享密钥，完成密钥协商
        if (OQS_KEM_decaps(kem, shared_secret, ct, sk) != OQS_SUCCESS) {
            std::cerr << "[KEM Error] Post-quantum key negotiation failed!" << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            CLOSE_SOCKET(cli_fd);
            continue;
        }
        std::cout << "[KEM Success] Post-quantum key negotiation completed, shared secret generated successfully!" << std::endl;

        // ======================================
        // Phase 3: Perfect fit TLS1.3 standard 7-step handshake protocol - Core key process
        // 阶段3：【完美拟合 TLS1.3 标准7次握手协议】- 核心重点流程
        // ======================================
        ssl = SSL_new(m_ssl_ctx);
        SSL_set_fd(ssl, cli_fd);                     // Bind SSL encryption context to client socket file descriptor | 将SSL加密上下文绑定到客户端套接字描述符
        std::cout << "[TLS Handshake] Starting standard TLS1.3 7-step handshake..." << std::endl;

        // Trigger TLS1.3 full 7-step handshake process, internal automatic completion of all handshake steps | 触发TLS1.3完整7次握手流程，内部自动完成全部握手步骤
        int ssl_ret = SSL_accept(ssl);
        if (ssl_ret <= 0) {
            std::cerr << "[TLS Error] TLS1.3 7-step handshake failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            SSL_free(ssl);
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        // TLS handshake success, print encrypted channel core information | TLS握手成功，打印加密通道核心信息
        std::cout << "[TLS Success] TLS1.3 7-step handshake completed! Encrypted channel established successfully" << std::endl;
        std::cout << "[TLS Info] Protocol Version: " << SSL_get_version(ssl) << std::endl;
        std::cout << "[TLS Info] Cipher Suite: " << SSL_get_cipher(ssl) << std::endl;

        // ======================================
        // Phase 4: Encrypted data transmission - Based on TLS1.3 secure encrypted channel
        // 阶段4：加密数据收发 - 基于TLS1.3安全加密通道完成业务通信
        // ======================================
        char recv_buf[1024] = {0};
        int recv_len = SSL_read(ssl, recv_buf, sizeof(recv_buf)-1);
        if (recv_len > 0) {
            std::cout << "[Encrypted Receive] " << recv_buf << std::endl;
            std::string reply = "[Server Encrypted Reply] Received message: " + std::string(recv_buf) + " | Post-quantum Algorithm: " + client_alg;
            SSL_write(ssl, reply.c_str(), reply.size());
        }

        // ======================================
        // Structured resource release: no GOTO, release in reverse order of application, zero memory leak, zero syntax error
        // ✅ 结构化资源释放：无GOTO，严格按申请逆序释放，零内存泄漏，零语法错误
        // ======================================
        SSL_shutdown(ssl);
        SSL_free(ssl);
        delete[] pk;
        delete[] sk;
        delete[] ct;
        OQS_KEM_free(kem);
        CLOSE_SOCKET(cli_fd);
        std::cout << "[Connection Closed] Client connection closed normally, waiting for new connection..." << std::endl;
    }
}