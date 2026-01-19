//
// Created by 22126 on 2026/1/19.
//

#ifndef MLKEM_KEM_CLIENT_H
#define MLKEM_KEM_CLIENT_H

#include "common.h"
#include <openssl/ssl.h>
#include <string>

class SwitchableKemClient {
private:
    SOCKET_FD m_cli_fd;
    SSL_CTX* m_ssl_ctx;
    std::string m_srv_ip;
    int m_srv_port;
    std::string m_alg_name;

public:
    // ✅ 核心修改：给算法参数增加默认值 ML-KEM-768，兼容无参调用
    SwitchableKemClient(const std::string& ip, int port, const std::string& alg_name = "ML-KEM-768");
    ~SwitchableKemClient();
    void connectAndCommunicate();
};

#endif // MLKEM_KEM_CLIENT_H