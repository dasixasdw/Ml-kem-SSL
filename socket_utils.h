/**
* @file socket_utils.h
 * @brief ML-KEM Post Quantum Cryptography Project - Cross-platform Socket Communication Tool Header File
 * @brief ML-KEM抗量子密码学项目 - 跨平台套接字通信工具头文件
 * @details Declare lightweight cross-platform socket function interfaces, encapsulate TCP socket creation and data transmission, unified call for whole project
 * @details 声明轻量级跨平台套接字功能接口，封装TCP套接字创建与数据收发，供全项目统一调用，屏蔽系统底层网络差异
 * @date 2026/01/19
 */

#ifndef MLKEM_SOCKET_UTILS_H
#define MLKEM_SOCKET_UTILS_H

#include "common.h"

// Create and initialize server socket: bind address and port + start listening
// 创建并初始化服务器Socket：绑定端口地址 + 启动监听
bool createServerSocket(SOCKET_FD& srv_fd, int port);

// Create and initialize client socket: establish connection to target server
// 创建并初始化客户端Socket：建立与目标服务器的连接
bool createClientSocket(SOCKET_FD& cli_fd, const std::string& ip, int port);

// Send data through socket, cross-platform compatible encapsulation
// 套接字数据发送，跨平台兼容封装
int sendData(SOCKET_FD fd, const void* buf, size_t len);

// Receive data through socket, cross-platform compatible encapsulation
// 套接字数据接收，跨平台兼容封装
int recvData(SOCKET_FD fd, void* buf, size_t len);

#endif // MLKEM_SOCKET_UTILS_H