//
// Created by 22126 on 2026/1/19.
//

#ifndef MLKEM_KEM_SERVER_H
#define MLKEM_KEM_SERVER_H

#include "common.h"
#include <string>
#include <unordered_map>
#include <openssl/ssl.h>
#include <oqs/oqs.h>

// 全局算法列表-仅声明 3种ML-KEM算法 (移除NTRU)
extern const std::unordered_map<std::string, KemAlgInfo> SUPPORTED_ALGS;

class MultiAlgKemServer
{
private:
    // ✅ 成员变量顺序 严格匹配cpp初始化列表，无警告
    SOCKET_FD m_srv_fd;
    SSL_CTX* m_ssl_ctx;
    std::string m_cert_path;
    std::string m_key_path;

public:
    explicit MultiAlgKemServer(const std::string& cert_path, const std::string& key_path);
    ~MultiAlgKemServer();
    void startServer();
};

#endif // MLKEM_KEM_SERVER_H