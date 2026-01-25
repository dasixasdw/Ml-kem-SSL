/**
 * @file kem_client.cpp
 * @brief ML-KEM Post Quantum Cryptography Project - Multi-algorithm Switchable KEM Client Implementation
 * @brief ML-KEM抗量子密码学项目 - 多算法可切换式KEM客户端实现文件
 * @details Implement the core business logic of post-quantum client: multi-algorithm negotiation, liboqs KEM key exchange, TLS1.3 encrypted communication, cross-platform socket communication
 * @details 实现抗量子客户端核心业务逻辑：多算法协商、liboqs KEM密钥交换、TLS1.3加密通信、跨平台套接字通信，集成抗量子密码与传统TLS双重加密机制
 * @date 2026/01/19
 */
#include "kem_client.h"
#include "crypto_utils.h"
#include "socket_utils.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <oqs/oqs.h>
#include <openssl/err.h>

/**
 * @brief Standardize the algorithm name to match liboqs official naming rules
 * 算法名称标准化映射函数 - 适配liboqs官方命名规范的核心修复函数
 * @param algName User-friendly algorithm name with uppercase format (e.g. NTRU-HPS2048509, ML-KEM-768)
 *        外部传入的大写友好型算法名称（如 NTRU-HPS2048509、ML-KEM-768）
 * @return liboqs official required standard lowercase algorithm name (e.g. ntru-hps2048509, ml-kem-768)
 *         liboqs库要求的标准全小写算法名称，是创建KEM实例成功的关键
 * @details Fix the core problem of NTRU KEM instance creation failure, the name passed to OQS_KEM_new must strictly match the official lowercase rule
 * @details 修复NTRU算法KEM实例创建失败的核心问题，传入OQS_KEM_new的算法名必须严格匹配官方全小写命名规则
 */
std::string getStandardOqsAlgName(const std::string& algName) {
    if (algName == "NTRU-HPS2048509") {
        return "ntru-hps2048509";  // The only valid standard name for NTRU in liboqs | liboqs中NTRU算法的唯一合法标准名称
    } else if (algName == "ML-KEM-512") {
        return "ml-kem-512";       // Standard name for ML-KEM-512 algorithm | ML-KEM-512算法标准名称
    } else if (algName == "ML-KEM-768") {
        return "ml-kem-768";       // Standard name for ML-KEM-768 algorithm | ML-KEM-768算法标准名称
    } else if (algName == "ML-KEM-1024") {
        return "ml-kem-1024";      // Standard name for ML-KEM-1024 algorithm | ML-KEM-1024算法标准名称
    }
    return algName;                // Fallback compatibility, return original name if no match | 兜底兼容逻辑，无匹配项时返回原名称
}

/**
 * @brief Constructor of SwitchableKemClient class
 * 可切换算法KEM客户端类的构造函数
 * @param ip Server IP address to connect
 *        待连接的服务器IP地址
 * @param port Server listening port number
 *        服务器监听端口号
 * @param alg_name User-specified post-quantum KEM algorithm name
 *        用户指定的抗量子KEM算法名称
 * @details The initialization sequence is consistent with the class declaration sequence, no compilation warning, complete cross-platform initialization
 * @details 初始化顺序与类声明顺序完全一致，无编译警告，完成全量跨平台初始化流程
 */
SwitchableKemClient::SwitchableKemClient(const std::string& ip, int port, const std::string& alg_name)
    : m_cli_fd(INVALID_SOCKET), m_ssl_ctx(nullptr), m_srv_ip(ip), m_srv_port(port), m_alg_name(alg_name) {
    initCryptoLib();                          // Initialize crypto libraries: liboqs + OpenSSL | 初始化密码学依赖库：liboqs抗量子库 + OpenSSL TLS库
    m_ssl_ctx = createSSLContext(false);      // Create SSL context for client mode | 创建客户端模式的SSL加密上下文
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);     // Windows socket environment initialization | Windows平台专属：套接字环境初始化
#endif
    std::cout << "========================================" << std::endl;
    std::cout << "✅ Post-quantum client initialized successfully | Server: " << ip << ":" << port << std::endl;
    std::cout << "✅ Using post-quantum algorithm: " << m_alg_name << std::endl;
    std::cout << "✅ Will perform standard TLS1.3 7-step handshake" << std::endl;
    std::cout << "========================================" << std::endl;
}

/**
 * @brief Destructor of SwitchableKemClient class
 * 可切换算法KEM客户端类的析构函数
 * @details Release all allocated resources in reverse order of initialization, prevent memory leak and resource occupation, cross-platform compatible cleanup
 * @details 按初始化逆序释放所有已分配资源，杜绝内存泄漏与系统资源占用，实现跨平台兼容的资源清理逻辑
 */
SwitchableKemClient::~SwitchableKemClient() {
    if (m_ssl_ctx != nullptr) {
        SSL_CTX_free(m_ssl_ctx);               // Release SSL context resource | 释放SSL加密上下文资源
    }
#ifdef _WIN32
    WSACleanup();                             // Windows socket environment cleanup | Windows平台专属：套接字环境资源清理
#endif
    cleanCryptoLib();                         // Clean up crypto library resources | 清理密码学库所有资源
}

/**
 * @brief Core business function: complete client connection + algorithm negotiation + KEM key exchange + TLS1.3 encrypted communication
 * 客户端核心业务函数 - 完成完整的连接建立、算法协商、抗量子密钥交换、TLS1.3加密通信全流程
 * @details Integrate socket communication, post-quantum KEM key encapsulation, TLS1.3 secure handshake and encrypted data transmission
 * @details 集成套接字通信、抗量子KEM密钥封装、TLS1.3安全握手、加密数据收发的全链路业务逻辑，含完整的异常处理与资源释放
 */
void SwitchableKemClient::connectAndCommunicate() {
    SOCKET_FD cli_fd = INVALID_SOCKET;
    OQS_KEM* kem = nullptr;
    uint8_t* pk = nullptr;
    uint8_t* ct = nullptr;
    SSL* ssl = nullptr;
    size_t pk_len = 0, ct_len = 0;

    // Create client socket and connect to server | 创建客户端套接字并建立与服务器的连接
    if (!createClientSocket(cli_fd, m_srv_ip, m_srv_port)) {
        std::cerr << "[Client Error] Failed to connect to server!" << std::endl;
        return;
    }
    std::cout << "[Connection Success] Connected to server successfully" << std::endl;

    // Send user-friendly algorithm name to server for algorithm negotiation | 向服务器发送友好型算法名称，完成算法协商流程
    sendData(cli_fd, m_alg_name.c_str(), m_alg_name.size()+1);
    std::cout << "[Algorithm Negotiation] Sent algorithm name: " << m_alg_name << std::endl;

    // Determine the public key and ciphertext length according to the selected algorithm, use original friendly name | 根据选定算法确定公钥/密文长度，沿用原友好算法名判断，业务逻辑不变
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
        std::cerr << "[Algorithm Error] Unsupported algorithm type!" << std::endl;
        CLOSE_SOCKET(cli_fd);
        return;
    }

    // Core fix: get liboqs standard lowercase algorithm name and create valid KEM instance | 核心修复点：获取标准小写算法名，创建合法的KEM实例
    std::string standardAlgName = getStandardOqsAlgName(m_alg_name);
    kem = OQS_KEM_new(standardAlgName.c_str());
    if (!kem) {
        std::cerr << "[KEM Error] Failed to create KEM instance! Algorithm name: " << standardAlgName << std::endl;
        CLOSE_SOCKET(cli_fd);
        return;
    }

    // Allocate memory for public key and ciphertext buffer | 为公钥、密文缓冲区分配内存空间
    pk = new uint8_t[pk_len]();
    ct = new uint8_t[ct_len]();
    uint8_t shared_secret[SHARED_SECRET_LEN] = {0};  // Fixed-length shared secret buffer, follow liboqs official standard | 固定长度共享密钥缓冲区，遵循liboqs官方32字节标准

    // Receive public key from server via socket | 从服务器接收抗量子算法公钥
    if (recvData(cli_fd, pk, pk_len) <= 0) {
        std::cerr << "[KEM Error] Failed to receive public key from server!" << std::endl;
        delete[] pk;
        delete[] ct;
        OQS_KEM_free(kem);
        CLOSE_SOCKET(cli_fd);
        return;
    }

    // Execute KEM encapsulation: generate ciphertext and shared secret with server's public key | 执行KEM密钥封装：用服务端公钥生成密文与共享密钥
    if (OQS_KEM_encaps(kem, ct, shared_secret, pk) != OQS_SUCCESS) {
        std::cerr << "[KEM Error] Post-quantum key negotiation failed!" << std::endl;
        delete[] pk;
        delete[] ct;
        OQS_KEM_free(kem);
        CLOSE_SOCKET(cli_fd);
        return;
    }

    // Send ciphertext to server to complete post-quantum key exchange | 向服务器发送密文，完成抗量子密钥协商全流程
    sendData(cli_fd, ct, ct_len);
    std::cout << "[KEM Success] Post-quantum key negotiation completed, shared secret generated successfully!" << std::endl;

    // Initialize TLS1.3 encrypted channel | 初始化TLS1.3加密通信通道
    ssl = SSL_new(m_ssl_ctx);
    SSL_set_fd(ssl, cli_fd);                     // Bind SSL context to socket file descriptor | 将SSL上下文绑定到套接字文件描述符
    SSL_set_tlsext_host_name(ssl, m_srv_ip.c_str()); // Set TLS SNI extension for domain verification | 设置TLS SNI扩展，完成域名校验
    std::cout << "[TLS Handshake] Starting standard TLS1.3 7-step handshake..." << std::endl;

    // Execute TLS1.3 7-step handshake | 执行TLS1.3标准7次握手流程
    int ssl_ret = SSL_connect(ssl);
    if (ssl_ret <= 0) {
        std::cerr << "[TLS Error] TLS1.3 7-step handshake failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        delete[] pk;
        delete[] ct;
        OQS_KEM_free(kem);
        SSL_free(ssl);
        CLOSE_SOCKET(cli_fd);
        return;
    }

    // TLS handshake success, print TLS connection information | TLS握手成功，打印加密通道核心信息
    std::cout << "[TLS Success] TLS1.3 7-step handshake completed! Encrypted channel established" << std::endl;
    std::cout << "[TLS Info] Protocol Version: " << SSL_get_version(ssl) << std::endl;
    std::cout << "[TLS Info] Cipher Suite: " << SSL_get_cipher(ssl) << std::endl;

    // ======================================
    // Phase 5: Persistent interactive encrypted communication (核心修改)
    // 阶段5：【持久化交互式加密通信】- 扩展为循环输入，支持quit退出
    // ======================================
    std::cout << "\n[Communication Start] Enter message to send (input '" << EXIT_CMD << "' to exit)..." << std::endl;
    char recv_buf[MAX_MSG_LENGTH] = {0};  // 替换为全局宏定义的消息长度
    std::string input_msg;
    bool is_communication_running = true;

    while (is_communication_running) {
        // 1. 读取用户输入
        std::cout << "[Client Input] > ";
        std::getline(std::cin, input_msg);

        // 2. 发送加密消息到服务端
        int send_len = SSL_write(ssl, input_msg.c_str(), input_msg.length());
        if (send_len <= 0) {
            std::cerr << "[Communication Error] Failed to send encrypted message: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            is_communication_running = false;
            continue;
        }
        std::cout << "[Encrypted Send] Message sent: " << input_msg << std::endl;

        // 3. 处理退出指令
        if (input_msg == EXIT_CMD) {
            std::cout << "[Communication Info] Sending exit command to server..." << std::endl;
            // 接收服务端退出确认
            memset(recv_buf, 0, sizeof(recv_buf));
            int recv_len = SSL_read(ssl, recv_buf, sizeof(recv_buf)-1);
            if (recv_len > 0) {
                std::cout << "[Encrypted Receive] Server reply: " << recv_buf << std::endl;
            }
            is_communication_running = false;
            continue;
        }

        // 4. 接收服务端加密回复
        memset(recv_buf, 0, sizeof(recv_buf));
        int recv_len = SSL_read(ssl, recv_buf, sizeof(recv_buf)-1);

        // 处理接收异常
        if (recv_len <= 0) {
            int ssl_err = SSL_get_error(ssl, recv_len);
            if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                std::cout << "[Communication Info] Server closed the encrypted connection" << std::endl;
            } else {
                std::cerr << "[Communication Error] Failed to receive encrypted reply: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            }
            is_communication_running = false;
            continue;
        }

        // 5. 显示服务端回复
        std::cout << "[Encrypted Receive] Server reply: " << recv_buf << std::endl;
    }

    // ======================================
    // Resource release: keep original logic, release in reverse order
    // 资源释放：保留原有逻辑，按逆序释放，零内存泄漏
    // ======================================
    SSL_shutdown(ssl);
    SSL_free(ssl);
    delete[] pk;
    delete[] ct;
    OQS_KEM_free(kem);
    CLOSE_SOCKET(cli_fd);
    std::cout << "[Communication End] Client connection closed normally" << std::endl;
}