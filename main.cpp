#include <iostream>
#include <string>
#include <unordered_map>
#include <oqs/oqs.h>
#include "kem_server.h"
#include "kem_client.h"
#include "common.h"

// 校验算法是否合法 - 仅保留ML-KEM系列
bool isSupportedAlgorithm(const std::string& algName) {
    return SUPPORTED_ALGS.find(algName) != SUPPORTED_ALGS.end();
}

// 打印帮助信息 - 移除NTRU算法说明
void printHelpInfo() {
    std::cout << "======================================= MLkem 抗量子加密通信工具 =======================================" << std::endl;
    std::cout << "✅ 版本说明：支持抗量子KEM协商 + TLS1.3标准7次握手，Windows/WSL/Linux 跨平台兼容" << std::endl;
    std::cout << "✅ 使用语法 | Usage：" << std::endl;
    std::cout << "   1. 查看帮助： ./MLkem -help    或    ./MLkem --help" << std::endl;
    std::cout << "   2. 启动服务端： ./MLkem server" << std::endl;
    std::cout << "   3. 启动客户端(默认算法)： ./MLkem client" << std::endl;
    std::cout << "   4. 启动客户端(指定算法)： ./MLkem client [Algorithm_Name]" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "✅ 支持的抗量子加密算法列表 | Supported Algorithms：" << std::endl;
    std::cout << "   [ ML-KEM-512    ] - 轻量级，密钥长度短，加密/协商速度最快，适合低性能设备" << std::endl;
    std::cout << "   [ ML-KEM-768    ] - 默认推荐，安全与速度完美平衡，NIST竞赛优胜算法，生产首选" << std::endl;
    std::cout << "   [ ML-KEM-1024   ] - 高安全级别，抗量子破解能力最强，适合金融/政务等高要求场景" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "✅ 运行说明 | Tips：" << std::endl;
    std::cout << "   1. 必须先启动服务端，再启动客户端，客户端默认连接 127.0.0.1:8888" << std::endl;
    std::cout << "   2. 服务端自动适配所有算法，无需任何配置，支持多客户端多算法同时接入" << std::endl;
    std::cout << "   3. 客户端切换算法无需重新编译，直接命令行传参即可，无需修改任何代码" << std::endl;
    std::cout << "========================================================================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    // 优先级最高：处理 -help / --help 帮助指令
    if (argc == 2) {
        std::string param = argv[1];
        if (param == "-help" || param == "--help") {
            printHelpInfo();
            return 0;
        }
    }

    // 校验参数个数，缺参数则提示帮助
    if (argc < 2) {
        std::cerr << "[参数错误] 缺少运行指令！执行 ./MLkem -help 查看完整使用方法" << std::endl;
        return -1;
    }

    std::string cmd = argv[1];
    // 启动服务器
    if (cmd == "server") {
        MultiAlgKemServer server(CERT_FILE, KEY_FILE);
        server.startServer();
    }
    // 启动客户端 - 支持命令行传参指定算法，免编译切换
    else if (cmd == "client") {
        std::string clientAlg = "ML-KEM-768"; // 默认算法
        // 传入算法参数则读取并校验
        if (argc == 3) {
            clientAlg = argv[2];
            if (!isSupportedAlgorithm(clientAlg)) {
                std::cerr << "[参数错误] 不支持的加密算法：" << clientAlg << std::endl;
                std::cerr << "✅ 支持的算法：ML-KEM-512 / ML-KEM-768 / ML-KEM-1024" << std::endl;
                return -1;
            }
        }
        // 启动客户端，传入指定算法
        SwitchableKemClient client(SERVER_IP, SERVER_PORT, clientAlg);
        client.connectAndCommunicate();
    }
    // 非法命令提示
    else {
        std::cerr << "[参数错误] 无效指令：" << cmd << "！执行 ./MLkem -help 查看完整使用方法" << std::endl;
        return -1;
    }

    return 0;
}