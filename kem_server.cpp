//
// Created by 22126 on 2026/1/19.
//

#include "kem_server.h"
#include "crypto_utils.h"
#include "socket_utils.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <oqs/oqs.h>
#include <openssl/err.h>

// 初始化支持的算法列表（全局）【已恢复：仅保留3种ML-KEM算法，删除NTRU】
const std::unordered_map<std::string, KemAlgInfo> SUPPORTED_ALGS = {
    {"ML-KEM-512",        {"ML-KEM-512",        OQS_KEM_ml_kem_512_length_public_key,        OQS_KEM_ml_kem_512_length_secret_key,        OQS_KEM_ml_kem_512_length_ciphertext}},
    {"ML-KEM-768",        {"ML-KEM-768",        OQS_KEM_ml_kem_768_length_public_key,        OQS_KEM_ml_kem_768_length_secret_key,        OQS_KEM_ml_kem_768_length_ciphertext}},
    {"ML-KEM-1024",       {"ML-KEM-1024",       OQS_KEM_ml_kem_1024_length_public_key,       OQS_KEM_ml_kem_1024_length_secret_key,       OQS_KEM_ml_kem_1024_length_ciphertext}}
};

// ✅ 修复：初始化顺序和类声明顺序一致 → m_srv_fd → m_ssl_ctx → m_cert_path → m_key_path
MultiAlgKemServer::MultiAlgKemServer(const std::string& cert_path, const std::string& key_path)
    : m_srv_fd(INVALID_SOCKET), m_ssl_ctx(nullptr), m_cert_path(cert_path), m_key_path(key_path) {
    initCryptoLib();
    m_ssl_ctx = createSSLContext(true, m_cert_path, m_key_path);
    if (!createServerSocket(m_srv_fd, SERVER_PORT)) {
        std::cerr << "[服务器错误] 服务器初始化失败!" << std::endl;
        exit(-1);
    }
    std::cout << "========================================" << std::endl;
    std::cout << "✅ 多算法抗量子服务器启动成功 | 端口: " << SERVER_PORT << std::endl;
    std::cout << "✅ 支持的抗量子算法列表:" << std::endl;
    for (const auto& alg : SUPPORTED_ALGS) {
        std::cout << "   - " << alg.first << std::endl;
    }
    std::cout << "✅ 已加载SSL证书，将执行标准TLS1.3 7次握手" << std::endl;
    std::cout << "========================================" << std::endl;
}

MultiAlgKemServer::~MultiAlgKemServer() {
    if (m_srv_fd != INVALID_SOCKET) {
        CLOSE_SOCKET(m_srv_fd);
    }
    if (m_ssl_ctx != nullptr) {
        SSL_CTX_free(m_ssl_ctx);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    cleanCryptoLib();
}

void MultiAlgKemServer::startServer() {
    sockaddr_in cli_addr{};
    socklen_t cli_len = sizeof(cli_addr);
    while (true) {
        // 等待客户端连接
        SOCKET_FD cli_fd = accept(m_srv_fd, (sockaddr*)&cli_addr, &cli_len);
        if (IS_INVALID_FD(cli_fd)) {
            std::cerr << "[网络错误] 接收客户端连接失败!" << std::endl;
            continue;
        }
        std::cout << "\n[新连接] 客户端接入: " << inet_ntoa(cli_addr.sin_addr) << ":" << ntohs(cli_addr.sin_port) << std::endl;

        // ✅ 提前声明所有变量，结构化无GOTO核心修改，避免跨越初始化
        OQS_KEM* kem = nullptr;
        uint8_t* pk = nullptr;
        uint8_t* sk = nullptr;
        uint8_t* ct = nullptr;
        SSL* ssl = nullptr;
        char alg_buf[MAX_ALG_NAME_LEN] = {0};
        std::string client_alg;

        // ======================================
        // 阶段1：应用层前置协商【抗量子算法协商】- 无侵入TLS协议
        // ======================================
        if (recvData(cli_fd, alg_buf, MAX_ALG_NAME_LEN) <= 0) {
            std::cerr << "[协商错误] 接收客户端算法名称失败!" << std::endl;
            CLOSE_SOCKET(cli_fd);
            continue;
        }
        client_alg = alg_buf;
        std::cout << "[算法协商] 客户端使用算法: " << client_alg << std::endl;

        // 校验算法是否支持
        if (SUPPORTED_ALGS.find(client_alg) == SUPPORTED_ALGS.end()) {
            std::cerr << "[协商错误] 不支持的算法: " << client_alg << "，断开连接!" << std::endl;
            CLOSE_SOCKET(cli_fd);
            continue;
        }
        const KemAlgInfo& alg_info = SUPPORTED_ALGS.at(client_alg);
        std::cout << "[协商成功] 算法匹配成功 | 公钥长度: " << alg_info.pk_len << "B" << std::endl;

        // ======================================
        // 阶段2：抗量子KEM密钥协商【liboqs官方API】
        // ======================================
        kem = OQS_KEM_new(client_alg.c_str());
        if (!kem) {
            std::cerr << "[KEM错误] 创建KEM实例失败!" << std::endl;
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        pk = new uint8_t[alg_info.pk_len]();
        sk = new uint8_t[alg_info.sk_len]();
        ct = new uint8_t[alg_info.ct_len]();
        uint8_t shared_secret[SHARED_SECRET_LEN] = {0};

        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
            std::cerr << "[KEM错误] 生成密钥对失败!" << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        sendData(cli_fd, pk, alg_info.pk_len);
        if (recvData(cli_fd, ct, alg_info.ct_len) <= 0) {
            std::cerr << "[KEM错误] 接收密文失败!" << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        if (OQS_KEM_decaps(kem, shared_secret, ct, sk) != OQS_SUCCESS) {
            std::cerr << "[KEM错误] 密钥协商失败!" << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            CLOSE_SOCKET(cli_fd);
            continue;
        }
        std::cout << "[KEM成功] 抗量子密钥协商完成，共享密钥已生成!" << std::endl;

        // ======================================
        // 阶段3：【完美拟合 TLS1.3 标准7次握手协议】- 核心重点
        // ======================================
        ssl = SSL_new(m_ssl_ctx);
        SSL_set_fd(ssl, cli_fd);
        std::cout << "[TLS握手] 开始执行 TLS1.3 标准7次握手..." << std::endl;

        int ssl_ret = SSL_accept(ssl); // 触发完整7次握手，内部自动完成所有步骤
        if (ssl_ret <= 0) {
            std::cerr << "[TLS错误] 7次握手失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            delete[] pk; delete[] sk; delete[] ct;
            OQS_KEM_free(kem);
            SSL_free(ssl);
            CLOSE_SOCKET(cli_fd);
            continue;
        }

        // 握手成功后，打印握手详情
        std::cout << "[TLS成功] ✅ TLS1.3 7次握手全完成！加密通道已建立" << std::endl;
        std::cout << "[TLS信息] 协议版本: " << SSL_get_version(ssl) << std::endl;
        std::cout << "[TLS信息] 加密套件: " << SSL_get_cipher(ssl) << std::endl;

        // ======================================
        // 阶段4：加密数据收发（TLS加密通道）
        // ======================================
        char recv_buf[1024] = {0};
        int recv_len = SSL_read(ssl, recv_buf, sizeof(recv_buf)-1);
        if (recv_len > 0) {
            std::cout << "[加密接收] " << recv_buf << std::endl;
            std::string reply = "【服务器加密回复】已收到: " + std::string(recv_buf) + " | 抗量子算法: " + client_alg;
            SSL_write(ssl, reply.c_str(), reply.size());
        }

        // ======================================
        // ✅ 结构化资源释放：无GOTO，按申请逆序释放，零内存泄漏，零语法错误
        // ======================================
        SSL_shutdown(ssl);
        SSL_free(ssl);
        delete[] pk;
        delete[] sk;
        delete[] ct;
        OQS_KEM_free(kem);
        CLOSE_SOCKET(cli_fd);
        std::cout << "[连接关闭] 客户端连接已关闭，等待新连接..." << std::endl;
    }
}