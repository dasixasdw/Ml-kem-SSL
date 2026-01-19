//
// Created by 22126 on 2026/1/19.
//

#ifndef MLKEM_SOCKET_UTILS_H
#define MLKEM_SOCKET_UTILS_H

#include "common.h"

// 创建并初始化服务器Socket：绑定+监听
bool createServerSocket(SOCKET_FD& srv_fd, int port);
// 创建并初始化客户端Socket：连接服务器
bool createClientSocket(SOCKET_FD& cli_fd, const std::string& ip, int port);
// 发送数据(跨平台封装)
int sendData(SOCKET_FD fd, const void* buf, size_t len);
// 接收数据(跨平台封装)
int recvData(SOCKET_FD fd, void* buf, size_t len);

#endif // MLKEM_SOCKET_UTILS_H