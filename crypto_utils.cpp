/**
 * @brief ML-KEM抗量子密码项目 密码学工具实现文件
 * @brief ML-KEM Post Quantum Cryptography Project - Cryptography Utilities Implementation
 * @details 封装密码学相关核心工具函数：密码库初始化/资源释放、SSL/TLS上下文创建，整合liboqs+OpenSSL双密码库调用逻辑
 * @details Encapsulate core cryptography utility functions: crypto library init/cleanup, SSL/TLS context creation, integrate liboqs & OpenSSL call logic
 * @date 2026/01/19
 */
#include "crypto_utils.h"
#include "common.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>
#include <iostream>

/**
 * @brief Initialize all dependent cryptography libraries
 * 初始化项目所有依赖的密码学库
 * @details Standard initialization for liboqs post-quantum library and OpenSSL TLS library, follow official recommended calling sequence
 * 对liboqs抗量子密码库、OpenSSL TLS加密库执行标准初始化流程，严格遵循官方推荐调用顺序
 */
void initCryptoLib() {
    OQS_init();                // Initialize liboqs post-quantum cryptography library | 初始化liboqs抗量子密码学库（官方标准调用）
    SSL_library_init();        // Initialize OpenSSL SSL/TLS core library | 初始化OpenSSL的SSL/TLS核心库
    OpenSSL_add_all_algorithms();  // Load all OpenSSL encryption/decryption algorithms | 加载OpenSSL所有加解密算法组件
    SSL_load_error_strings();  // Load OpenSSL SSL/TLS related error description strings | 加载OpenSSL的SSL/TLS相关错误描述字符串
    ERR_load_crypto_strings(); // Load OpenSSL crypto module related error description strings | 加载OpenSSL密码学模块相关错误描述字符串
}

/**
 * @brief Release all resources occupied by cryptography libraries
 * 释放密码学库占用的所有资源
 * @details Standard resource cleanup for OpenSSL library, prevent memory leaks and resource occupation
 * 对OpenSSL库执行标准的资源清理流程，防止内存泄漏与系统资源占用
 * @note liboqs has no independent cleanup function, follow official document description
 * 注：liboqs无独立的资源清理函数，此为官方文档标注的标准使用方式
 */
void cleanCryptoLib() {
    EVP_cleanup();                 // Clean up OpenSSL EVP encryption algorithm resources | 清理OpenSSL EVP加密算法资源
    ERR_free_strings();            // Release OpenSSL error string resources | 释放OpenSSL错误字符串资源
    CRYPTO_cleanup_all_ex_data();  // Clean up all extended data of OpenSSL crypto module | 清理OpenSSL密码学模块的所有扩展数据
}

/**
 * @brief Create and configure SSL/TLS encryption context
 * 创建并配置SSL/TLS加密通信上下文
 * @param is_server Mark current role is server or client, bool type: true=server, false=client
 *        当前角色标识，布尔类型：true=服务端，false=客户端
 * @param cert_path File path of TLS certificate file (PEM format)
 *        TLS证书文件的路径（PEM格式）
 * @param key_path File path of TLS private key file (PEM format)
 *        TLS私钥文件的路径（PEM格式）
 * @return Valid SSL_CTX* context pointer on success, exit program directly on failure
 *         创建成功返回有效的SSL_CTX上下文指针，创建失败直接退出程序
 * @details Adopt OpenSSL 3.6.0 recommended writing method, compatible with TLS1.3/TLS1.2, highest security level configuration
 * 采用OpenSSL 3.6.0官方推荐写法，兼容TLS1.3/TLS1.2协议，配置最高适配的安全等级
 */
SSL_CTX* createSSLContext(bool is_server, const std::string& cert_path, const std::string& key_path) {
    // Create TLS context, TLS_method() is compatible with TLS1.3 and TLS1.2, OpenSSL 3.6.0 recommended | 创建TLS上下文，TLS_method()兼容TLS1.3/TLS1.2，OpenSSL3.6.0推荐写法
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        std::cerr << "[加密错误] SSL上下文创建失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(-1);
    }

    // Set OpenSSL security level 3, meet the latest security specification of OpenSSL 3.x | 设置OpenSSL安全等级3，符合OpenSSL3.x新版安全规范
    SSL_CTX_set_security_level(ctx, 3);

    if (is_server) {
        // Server side: load certificate and private key for identity authentication and encryption | 服务端逻辑：加载证书与私钥，用于身份认证和加密通信
        if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "[加密错误] 加载证书失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(-1);
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "[加密错误] 加载私钥失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(-1);
        }
        // Verify the consistency of private key and certificate, mandatory security check | 校验私钥与证书的一致性，服务端强制安全校验
        if (!SSL_CTX_check_private_key(ctx)) {
            std::cerr << "[加密错误] 私钥与证书不匹配!" << std::endl;
            exit(-1);
        }
    } else {
        // Client side: skip certificate verification for test environment | 客户端逻辑：测试环境下跳过证书校验
        // Note: enable certificate verification in production environment for security | 注意：生产环境建议开启证书校验，提升通信安全性
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    return ctx;
}