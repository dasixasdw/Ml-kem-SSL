//
// Created by 22126 on 2026/1/19.
//

#include "socket_utils.h"
#include "common.h"
#include <iostream>
#include <cstring>

bool createServerSocket(SOCKET_FD& srv_fd, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[网络错误] Windows Socket初始化失败!" << std::endl;
        return false;
    }
#endif
    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID_FD(srv_fd)) {
        std::cerr << "[网络错误] 创建Socket失败!" << std::endl;
        return false;
    }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SOCKET_REUSE_FLAG, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "[网络错误] 绑定端口失败!" << std::endl;
        return false;
    }
    if (listen(srv_fd, 10) == -1) { // 支持10个并发连接
        std::cerr << "[网络错误] 监听端口失败!" << std::endl;
        return false;
    }
    return true;
}

bool createClientSocket(SOCKET_FD& cli_fd, const std::string& ip, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    cli_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID_FD(cli_fd)) {
        std::cerr << "[网络错误] 创建Socket失败!" << std::endl;
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "[网络错误] IP地址格式错误!" << std::endl;
        return false;
    }

    if (connect(cli_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "[网络错误] 连接服务器失败!" << std::endl;
        return false;
    }
    return true;
}

int sendData(SOCKET_FD fd, const void* buf, size_t len) {
#ifdef _WIN32
    return send(fd, (const char*)buf, (int)len, 0);
#else
    return send(fd, buf, len, 0);
#endif
}

int recvData(SOCKET_FD fd, void* buf, size_t len) {
#ifdef _WIN32
    return recv(fd, (char*)buf, (int)len, 0);
#else
    return recv(fd, buf, len, 0);
#endif
}