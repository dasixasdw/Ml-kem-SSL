//
// Created by 22126 on 2026/1/19.
//

#include "kem_client.h"
#include "crypto_utils.h"
#include "socket_utils.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <oqs/oqs.h>
#include <openssl/err.h>

// ✅ ✨ 核心新增：算法名称标准化映射函数（修复NTRU创建失败的关键！）
// 输入：用户传参的友好名称(如NTRU-HPS2048509/ML-KEM-768)
// 输出：liboqs官方要求的标准小写名称(如ntru-hps2048509/ml-kem-768)
std::string getStandardOqsAlgName(const std::string& algName) {
    if (algName == "NTRU-HPS2048509") {
        return "ntru-hps2048509"; // NTRU唯一合法标准名，全小写无横杠
    } else if (algName == "ML-KEM-512") {
        return "ml-kem-512";
    } else if (algName == "ML-KEM-768") {
        return "ml-kem-768";
    } else if (algName == "ML-KEM-1024") {
        return "ml-kem-1024";
    }
    return algName; // 默认返回原名称，兜底兼容
}

// 初始化顺序和类声明顺序一致，无警告
SwitchableKemClient::SwitchableKemClient(const std::string& ip, int port, const std::string& alg_name)
    : m_cli_fd(INVALID_SOCKET), m_ssl_ctx(nullptr), m_srv_ip(ip), m_srv_port(port), m_alg_name(alg_name) {
    initCryptoLib();
    m_ssl_ctx = createSSLContext(false); // 客户端SSL上下文
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    std::cout << "========================================" << std::endl;
    std::cout << "✅ 抗量子客户端初始化成功 | 服务器: " << ip << ":" << port << std::endl;
    std::cout << "✅ 使用抗量子算法: " << m_alg_name << std::endl;
    std::cout << "✅ 将执行标准TLS1.3 7次握手" << std::endl;
    std::cout << "========================================" << std::endl;
}

SwitchableKemClient::~SwitchableKemClient() {
    if (m_ssl_ctx != nullptr) {
        SSL_CTX_free(m_ssl_ctx);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    cleanCryptoLib();
}

void SwitchableKemClient::connectAndCommunicate() {
    SOCKET_FD cli_fd = INVALID_SOCKET;
    OQS_KEM* kem = nullptr;
    uint8_t* pk = nullptr;
    uint8_t* ct = nullptr;
    SSL* ssl = nullptr;
    size_t pk_len = 0, ct_len = 0;

    if (!createClientSocket(cli_fd, m_srv_ip, m_srv_port)) {
        std::cerr << "[客户端错误] 连接服务器失败!" << std::endl;
        return;
    }
    std::cout << "[连接成功] 已连接到服务器" << std::endl;

    // 向服务器发送【用户传参的友好算法名】，服务器正常识别
    sendData(cli_fd, m_alg_name.c_str(), m_alg_name.size()+1);
    std::cout << "[算法协商] 已发送算法名称: " << m_alg_name << std::endl;

    // ✅ 算法密钥长度判断 - 依然用原友好名称，逻辑不变
    if (m_alg_name == "ML-KEM-512") {
        pk_len = OQS_KEM_ml_kem_512_length_public_key;
        ct_len = OQS_KEM_ml_kem_512_length_ciphertext;
    } else if (m_alg_name == "ML-KEM-768") {
        pk_len = OQS_KEM_ml_kem_768_length_public_key;
        ct_len = OQS_KEM_ml_kem_768_length_ciphertext;
    } else if (m_alg_name == "ML-KEM-1024") {
        pk_len = OQS_KEM_ml_kem_1024_length_public_key;
        ct_len = OQS_KEM_ml_kem_1024_length_ciphertext;
    } else if (m_alg_name == "NTRU-HPS2048509") {
        pk_len = OQS_KEM_ntru_hps2048509_length_public_key;
        ct_len = OQS_KEM_ntru_hps2048509_length_ciphertext;
    } else {
        std::cerr << "[算法错误] 不支持的算法!" << std::endl;
        CLOSE_SOCKET(cli_fd);
        return;
    }

    // ✅ ✨ 核心修复：获取liboqs标准算法名，创建KEM实例（解决NTRU失败的关键！）
    std::string standardAlgName = getStandardOqsAlgName(m_alg_name);
    kem = OQS_KEM_new(standardAlgName.c_str());
    if (!kem) {
        std::cerr << "[KEM错误] 创建KEM实例失败! 算法名: " << standardAlgName << std::endl;
        CLOSE_SOCKET(cli_fd);
        return;
    }

    pk = new uint8_t[pk_len]();
    ct = new uint8_t[ct_len]();
    uint8_t shared_secret[SHARED_SECRET_LEN] = {0};

    if (recvData(cli_fd, pk, pk_len) <= 0) {
        std::cerr << "[KEM错误] 接收公钥失败!" << std::endl;
        delete[] pk;
        delete[] ct;
        OQS_KEM_free(kem);
        CLOSE_SOCKET(cli_fd);
        return;
    }

    if (OQS_KEM_encaps(kem, ct, shared_secret, pk) != OQS_SUCCESS) {
        std::cerr << "[KEM错误] 密钥协商失败!" << std::endl;
        delete[] pk;
        delete[] ct;
        OQS_KEM_free(kem);
        CLOSE_SOCKET(cli_fd);
        return;
    }

    sendData(cli_fd, ct, ct_len);
    std::cout << "[KEM成功] 抗量子密钥协商完成，共享密钥已生成!" << std::endl;

    ssl = SSL_new(m_ssl_ctx);
    SSL_set_fd(ssl, cli_fd);
    SSL_set_tlsext_host_name(ssl, m_srv_ip.c_str());
    std::cout << "[TLS握手] 开始执行 TLS1.3 标准7次握手..." << std::endl;

    int ssl_ret = SSL_connect(ssl);
    if (ssl_ret <= 0) {
        std::cerr << "[TLS错误] 7次握手失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        delete[] pk;
        delete[] ct;
        OQS_KEM_free(kem);
        SSL_free(ssl);
        CLOSE_SOCKET(cli_fd);
        return;
    }

    std::cout << "[TLS成功] ✅ TLS1.3 7次握手全完成！加密通道已建立" << std::endl;
    std::cout << "[TLS信息] 协议版本: " << SSL_get_version(ssl) << std::endl;
    std::cout << "[TLS信息] 加密套件: " << SSL_get_cipher(ssl) << std::endl;

    std::string send_msg = "Hello 多算法抗量子服务器! 客户端算法: " + m_alg_name + " | TLS1.3加密通信";
    SSL_write(ssl, send_msg.c_str(), send_msg.size());
    std::cout << "[加密发送] " << send_msg << std::endl;

    char recv_buf[1024] = {0};
    int recv_len = SSL_read(ssl, recv_buf, sizeof(recv_buf)-1);
    if (recv_len > 0) {
        std::cout << "[加密接收] " << recv_buf << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    delete[] pk;
    delete[] ct;
    OQS_KEM_free(kem);
    CLOSE_SOCKET(cli_fd);
    std::cout << "[通信结束] 客户端连接已关闭" << std::endl;
}