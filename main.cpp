/**
 * @file main.cpp
 * @brief ML-KEM Post Quantum Cryptography Project - Entry Main Function File
 * @brief ML-KEM抗量子密码学项目 - 程序入口主函数文件
 * @details Project startup scheduling center, provide command line parameter parsing, algorithm validity verification, server/client process startup, support runtime algorithm switching without recompilation
 * @details 项目启动调度核心，提供命令行参数解析、算法合法性校验、服务端/客户端进程启动，支持运行时免编译切换加密算法，全平台兼容
 * @date 2026/01/19
 */
#include <iostream>
#include <string>
#include <unordered_map>
#include <oqs/oqs.h>
#include "kem_server.h"
#include "kem_client.h"
#include "common.h"

/**
 * @brief Verify whether the specified algorithm is in the server supported list
 * 校验指定的抗量子算法是否为服务端支持的合法算法
 * @param algName Name of the post-quantum algorithm to be verified
 *        待校验的抗量子算法名称
 * @return true if the algorithm is supported, false otherwise
 *         算法合法返回true，不支持则返回false
 * @details Only verify ML-KEM series algorithms, remove NTRU related verification logic, unified algorithm specification
 * @details 仅校验ML-KEM系列标准算法，移除NTRU相关校验逻辑，算法体系标准化
 */
bool isSupportedAlgorithm(const std::string& algName) {
    return SUPPORTED_ALGS.find(algName) != SUPPORTED_ALGS.end();
}

/**
 * @brief Print the project help information and usage specification
 * 打印项目完整的帮助信息与使用规范
 * @details Remove NTRU algorithm description, only display ML-KEM series algorithms, supplement algorithm characteristics and applicable scenarios
 * @details 移除NTRU算法说明，仅展示ML-KEM系列标准算法，补充各算法特性与适用场景，提升使用可读性
 */
void printHelpInfo() {
    std::cout << "======================================= MLkem Post Quantum Encryption Communication Tool =======================================" << std::endl;
    std::cout << "✅ Version Info: Support post-quantum KEM negotiation + TLS1.3 standard 7-step handshake, cross-platform compatible with Windows/WSL/Linux" << std::endl;
    std::cout << "✅ Usage Syntax | 使用语法：" << std::endl;
    std::cout << "   1. Show help    : ./MLkem -help    or    ./MLkem --help" << std::endl;
    std::cout << "   2. Start server : ./MLkem server" << std::endl;
    std::cout << "   3. Start client (default algorithm) : ./MLkem client" << std::endl;
    std::cout << "   4. Start client (assign algorithm)  : ./MLkem client [Algorithm_Name]" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "✅ Supported Post-quantum Encryption Algorithms | 支持的抗量子加密算法列表：" << std::endl;
    std::cout << "   [ ML-KEM-512    ] - Lightweight, short key length, fastest encryption/negotiation speed, suitable for low-performance devices" << std::endl;
    std::cout << "   [ ML-KEM-768    ] - Recommended by default, perfect balance of security and speed, NIST competition winning algorithm, production preferred" << std::endl;
    std::cout << "   [ ML-KEM-1024   ] - High security level, strongest anti-quantum cracking ability, suitable for financial/government high-demand scenarios" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "✅ Running Instructions | 运行说明：" << std::endl;
    std::cout << "   1. Must start the server first, then the client, the client connects to 127.0.0.1:8888 by default" << std::endl;
    std::cout << "   2. The server automatically adapts all algorithms without any configuration, supports multi-client and multi-algorithm access simultaneously" << std::endl;
    std::cout << "   3. Client algorithm switching does not require recompilation, just pass parameters in the command line without modifying any code" << std::endl;
    std::cout << "=================================================================================================================================" << std::endl;
}

/**
 * @brief Project entry main function
 * 项目程序入口主函数
 * @param argc Number of command line input parameters
 *        命令行传入的参数个数
 * @param argv Command line parameter array
 *        命令行参数数组
 * @return 0 for normal exit, -1 for abnormal exit with parameter/algorithm error
 *         正常退出返回0，参数错误/算法错误等异常退出返回-1
 * @details Core function: parameter parsing, help command processing, server/client startup scheduling, algorithm parameter verification
 * @details 核心功能：参数解析、帮助指令优先处理、服务端/客户端启动调度、算法参数合法性校验，是整个项目的总入口
 */
int main(int argc, char* argv[]) {
    // Highest priority: process help command, respond first without other logic judgment
    // 优先级最高：处理帮助指令，优先响应，不执行其他逻辑判断
    if (argc == 2) {
        std::string param = argv[1];
        if (param == "-help" || param == "--help") {
            printHelpInfo();
            return 0;
        }
    }

    // Parameter validity check: exit with error if the number of parameters is insufficient
    // 参数合法性校验：参数个数不足则打印错误信息并退出程序
    if (argc < 2) {
        std::cerr << "[Parameter Error] Missing running command! Execute ./MLkem -help to view the complete usage method" << std::endl;
        return -1;
    }

    std::string cmd = argv[1];
    // Startup logic: start multi-algorithm post-quantum server
    // 启动逻辑分支一：启动多算法抗量子服务端
    if (cmd == "server") {
        MultiAlgKemServer server(CERT_FILE, KEY_FILE);
        server.startServer();
    }
    // Startup logic: start switchable post-quantum client, support runtime algorithm assignment
    // 启动逻辑分支二：启动可切换算法的抗量子客户端，支持运行时指定加密算法
    else if (cmd == "client") {
        std::string clientAlg = "ML-KEM-768";  // Default encryption algorithm, the most balanced choice | 默认加密算法，安全与性能最优平衡选型
        // Read and性能最优平衡选型
        // Read and verify the algorithm parameter passed by the command line
        // 命令行传入了算法参数，则读取参数并校验算法合法性
        if (argc == 3) {
            clientAlg = argv[2];
            if (!isSupportedAlgorithm(clientAlg)) {
                std::cerr << "[Parameter Error] Unsupported encryption algorithm: " << clientAlg << std::endl;
                std::cerr << "✅ Supported algorithms: ML-KEM-512 / ML-KEM-768 / ML-KEM-1024" << std::endl;
                return -1;
            }
        }
        // Start the client with the specified algorithm, connect to the default server address and port
        // 启动客户端并传入指定算法，连接默认的服务器地址与端口
        SwitchableKemClient client(SERVER_IP, SERVER_PORT, clientAlg);
        client.connectAndCommunicate();
    }
    // Abnormal logic: illegal command input, prompt error information
    // 异常逻辑分支：输入了非法指令，打印错误提示信息
    else {
        std::cerr << "[Parameter Error] Invalid command: " << cmd << "! Execute ./MLkem -help to view the complete usage method" << std::endl;
        return -1;
    }

    return 0;
}