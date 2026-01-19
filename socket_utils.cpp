/**
 * @file socket_utils.cpp
 * @brief ML-KEM Post Quantum Cryptography Project - Cross-platform Socket Communication Tool Implementation
 * @brief ML-KEM抗量子密码学项目 - 跨平台套接字通信工具实现文件
 * @details Encapsulate universal socket communication functions, implement cross-platform compatible server/client socket creation, data send/receive, solve the system differences of socket API between Windows and Linux/WSL
 * @details 封装通用的套接字通信工具函数，实现跨平台兼容的服务端/客户端套接字创建、数据收发功能，解决Windows与Linux/WSL之间的Socket接口系统差异性问题
 * @date 2026/01/19
 */
#include "socket_utils.h"
#include "common.h"
#include <iostream>
#include <cstring>

/**
 * @brief Create and initialize server-side listening socket
 * 创建并初始化服务端监听套接字
 * @param srv_fd Reference of server socket file descriptor, save the created valid socket handle
 *        服务端套接字文件描述符的引用，用于保存创建后的有效套接字句柄
 * @param port The port number that the server needs to bind and listen to
 *        服务端需要绑定并监听的端口号
 * @return true for successful socket creation and initialization, false for failure
 *         套接字创建及初始化成功返回true，失败则返回false
 * @details Complete process: socket environment init → create socket → set port reuse → bind address/port → start listening
 * @details 完成完整服务端套接字流程：套接字环境初始化 → 创建套接字 → 设置端口复用 → 绑定地址端口 → 启动监听
 */
bool createServerSocket(SOCKET_FD& srv_fd, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    // Windows platform exclusive: initialize Winsock 2.2 socket environment | Windows平台专属：初始化Winsock 2.2版本套接字运行环境
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Network Error] Windows Socket environment initialization failed!" << std::endl;
        return false;
    }
#endif
    // Create IPv4 stream socket based on TCP protocol | 创建基于TCP协议的IPv4流式套接字
    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID_FD(srv_fd)) {
        std::cerr << "[Network Error] Failed to create server socket!" << std::endl;
        return false;
    }

    // Set socket port reuse attribute to solve port occupation problem after restart | 设置套接字端口复用属性，解决服务端重启后的端口占用问题
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SOCKET_REUSE_FLAG, (const char*)&opt, sizeof(opt));

    // Initialize IPv4 socket address structure | 初始化IPv4套接字地址结构体
    sockaddr_in addr{};
    addr.sin_family = AF_INET;                // Use IPv4 address protocol | 使用IPv4地址协议簇
    addr.sin_addr.s_addr = INADDR_ANY;        // Bind all local network card addresses | 绑定本机所有网卡地址
    addr.sin_port = htons(port);              // Convert host byte order to network byte order | 端口号主机字节序转网络字节序

    // Bind socket to specified address and port | 将套接字绑定到指定的地址与端口
    if (bind(srv_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "[Network Error] Failed to bind listening port!" << std::endl;
        return false;
    }
    // Start listening for client connection requests, support 10 concurrent connections | 启动监听客户端连接请求，最大支持10个并发连接队列
    if (listen(srv_fd, 10) == -1) {
        std::cerr << "[Network Error] Failed to start port listening!" << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Create and initialize client-side socket, connect to target server
 * 创建并初始化客户端套接字，完成与目标服务器的连接
 * @param cli_fd Reference of client socket file descriptor, save the created valid socket handle
 *        客户端套接字文件描述符的引用，用于保存创建后的有效套接字句柄
 * @param ip IP address of the target server to connect
 *        待连接的目标服务器IP地址
 * @param port Listening port number of the target server
 *        目标服务器的监听端口号
 * @return true for successful connection, false for socket creation/connection failure
 *         连接成功返回true，套接字创建或连接失败则返回false
 * @details Complete process: socket environment init → create socket → initialize server address → establish connection with server
 * @details 完成完整客户端套接字流程：套接字环境初始化 → 创建套接字 → 初始化服务端地址 → 与服务端建立连接
 */
bool createClientSocket(SOCKET_FD& cli_fd, const std::string& ip, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    // Windows platform exclusive: initialize Winsock socket environment | Windows平台专属：初始化Winsock套接字运行环境
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    // Create IPv4 stream socket based on TCP protocol | 创建基于TCP协议的IPv4流式套接字
    cli_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID_FD(cli_fd)) {
        std::cerr << "[Network Error] Failed to create client socket!" << std::endl;
        return false;
    }

    // Initialize IPv4 socket address structure of target server | 初始化目标服务器的IPv4套接字地址结构体
    sockaddr_in addr{};
    addr.sin_family = AF_INET;                // Use IPv4 address protocol | 使用IPv4地址协议簇
    addr.sin_port = htons(port);              // Convert port number to network byte order | 端口号主机字节序转网络字节序
    // Convert IP address from string format to network byte order format | 将字符串格式的IP地址转换为网络字节序格式
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "[Network Error] Invalid server IP address format!" << std::endl;
        return false;
    }

    // Establish TCP connection with the target server | 与目标服务器建立TCP连接
    if (connect(cli_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "[Network Error] Failed to connect to target server!" << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Cross-platform compatible data sending function
 * 跨平台兼容的通用数据发送函数
 * @param fd Valid socket file descriptor for communication
 *        用于通信的有效套接字文件描述符
 * @param buf Pointer to the data buffer to be sent
 *        待发送数据缓冲区的指针
 * @param len The length of the data to be sent (unit: byte)
 *        待发送数据的字节长度
 * @return The actual number of bytes sent on success, SOCKET_ERROR on failure
 *         成功返回实际发送的字节数，失败返回套接字错误码
 * @details Unify the parameter type differences of send function between Windows and Linux, solve the int/size_t type mismatch problem
 * @details 统一Windows与Linux平台send函数的参数类型差异，解决int/size_t类型不匹配编译警告
 */
int sendData(SOCKET_FD fd, const void* buf, size_t len) {
#ifdef _WIN32
    return send(fd, (const char*)buf, (int)len, 0);  // Windows send requires int type length | Windows平台send函数要求长度为int类型
#else
    return send(fd, buf, len, 0);                   // Linux send supports size_t type length natively | Linux平台原生支持size_t类型长度
#endif
}

/**
 * @brief Cross-platform compatible data receiving function
 * 跨平台兼容的通用数据接收函数
 * @param fd Valid socket file descriptor for communication
 *        用于通信的有效套接字文件描述符
 * @param buf Pointer to the buffer for storing received data
 *        用于存储接收数据的缓冲区指针
 * @param len The maximum length of data to receive (unit: byte)
 *        待接收数据的最大字节长度
 * @return The actual number of bytes received on success, SOCKET_ERROR on failure, 0 means peer closed connection
 *         成功返回实际接收的字节数，失败返回套接字错误码，返回0表示对端关闭连接
 * @details Unify the parameter type differences of recv function between Windows and Linux, achieve seamless cross-platform call
 * @details 统一Windows与Linux平台recv函数的参数类型差异，实现无缝跨平台调用
 */
int recvData(SOCKET_FD fd, void* buf, size_t len) {
#ifdef _WIN32
    return recv(fd, (char*)buf, (int)len, 0);  // Windows recv requires int type length | Windows平台recv函数要求长度为int类型
#else
    return recv(fd, buf, len, 0);             // Linux recv supports size_t type length natively | Linux平台原生支持size_t类型长度
#endif
}