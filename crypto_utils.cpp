//
// Created by 22126 on 2026/1/19.
//
#include "crypto_utils.h"
#include "common.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>
#include <iostream>

void initCryptoLib() {
    OQS_init(); // liboqs初始化(官方标准调用)
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

void cleanCryptoLib() {
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}

SSL_CTX* createSSLContext(bool is_server, const std::string& cert_path, const std::string& key_path) {
    // ✅ OpenSSL3.6.0 推荐写法：TLS_method() 兼容TLS1.3/1.2，完美适配
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        std::cerr << "[加密错误] SSL上下文创建失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(-1);
    }
    // ✅ OpenSSL3.6.0 安全配置：设置安全等级3，符合新版规范
    SSL_CTX_set_security_level(ctx, 3);

    if (is_server) {
        // 服务器加载证书和私钥
        if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "[加密错误] 加载证书失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(-1);
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "[加密错误] 加载私钥失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(-1);
        }
        if (!SSL_CTX_check_private_key(ctx)) {
            std::cerr << "[加密错误] 私钥与证书不匹配!" << std::endl;
            exit(-1);
        }
    } else {
        // 客户端跳过证书校验(测试环境用，生产环境可开启校验)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    return ctx;
}