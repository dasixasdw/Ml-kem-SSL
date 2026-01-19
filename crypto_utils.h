//
// Created by 22126 on 2026/1/19.
//

#ifndef MLKEM_CRYPTO_UTILS_H
#define MLKEM_CRYPTO_UTILS_H

#include <string>
#include <openssl/ssl.h>

// 初始化加密库：liboqs + OpenSSL
void initCryptoLib();
// 清理加密库资源
void cleanCryptoLib();
// 创建SSL上下文 (is_server=true:服务器端, false:客户端)
SSL_CTX* createSSLContext(bool is_server, const std::string& cert_path = "", const std::string& key_path = "");

#endif // MLKEM_CRYPTO_UTILS_H