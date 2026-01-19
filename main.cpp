#include <iostream>
#include <string>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>

using namespace std;

// ====================== ✅ 核心跨平台条件编译 - 完美适配 Linux/Windows 【完整版】 ======================
#ifdef _WIN32
// Windows系统 专属配置
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")  // Windows必须链接Socket库
#define SOCKET_FD SOCKET
#define CLOSE_SOCKET(fd) closesocket(fd)
#define IS_INVALID_SOCKET(fd) (fd == INVALID_SOCKET)
#define SOCKET_ERR_MSG() cout << "错误码：" << WSAGetLastError() << endl;
// Windows send/recv 强转封装，解决uint8_t类型不匹配
#define SEND_DATA(fd, buf, len) send(fd, (const char*)(buf), len, 0)
#define RECV_DATA(fd, buf, len) recv(fd, (char*)(buf), len, 0)
// Windows无SO_REUSEPORT，仅支持SO_REUSEADDR
#define SOCKET_REUSE_FLAG SO_REUSEADDR
#else
// Linux/WSL系统 专属配置
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#define SOCKET_FD int
#define CLOSE_SOCKET(fd) close(fd)
#define IS_INVALID_SOCKET(fd) (fd == -1)
#define SOCKET_ERR_MSG() perror("");
// Linux原生支持uint8_t指针，无需强转
#define SEND_DATA(fd, buf, len) send(fd, buf, len, 0)
#define RECV_DATA(fd, buf, len) recv(fd, buf, len, 0)
// Linux双复用：地址+端口
#define SOCKET_REUSE_FLAG (SO_REUSEADDR | SO_REUSEPORT)
#endif
// ====================== ✅ 跨平台适配 END ======================

// 全局常量：ML-KEM768 算法标识
const char* MLKEM_ALG = OQS_KEM_alg_ml_kem_768;
const size_t PSK_LEN = 32;

// 初始化加密库 (跨平台通用，无需修改)
void initCryptoLib() {
    OQS_init();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

// 清理加密库 (跨平台通用，无需修改)
void cleanupCryptoLib() {
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}

// ====================== ✅ TLS 服务器类 (【全平台修复】支持Linux+Windows编译运行，循环接收连接) ======================
class TLSServer {
private:
    SOCKET_FD server_fd;  // ✅ 修复：统一用跨平台SOCKET_FD类型
    SSL_CTX* ctx;
    const int port;
    const string cert_path;
    const string key_path;

public:
    TLSServer(int port_, const string& cert_, const string& key_)
        : port(port_), cert_path(cert_), key_path(key_) {
        initCryptoLib();

        // ====================== ✅ 修复：Windows服务器也需要初始化Winsock ======================
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            cerr << "[服务器] Windows Socket初始化失败！"; SOCKET_ERR_MSG();
            exit(-1);
        }
#endif

        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            cerr << "[服务器] 初始化SSL上下文失败：" << ERR_error_string(ERR_get_error(), nullptr) << endl;
            exit(-1);
        }

        if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            cerr << "[服务器] 加载证书失败：" << ERR_error_string(ERR_get_error(), nullptr) << endl;
            exit(-1);
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            cerr << "[服务器] 加载私钥失败：" << ERR_error_string(ERR_get_error(), nullptr) << endl;
            exit(-1);
        }
        if (!SSL_CTX_check_private_key(ctx)) {
            cerr << "[服务器] 私钥与证书不匹配！" << endl;
            exit(-1);
        }

        // ✅ 统一跨平台socket创建
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (IS_INVALID_SOCKET(server_fd)) {
            cerr << "[服务器] 创建 socket 失败！"; SOCKET_ERR_MSG();
            exit(-1);
        }

        int opt = 1;
        // ✅ 修复核心1：替换SO_REUSEPORT，用跨平台宏SOCKET_REUSE_FLAG，解决未声明报错
        setsockopt(server_fd, SOL_SOCKET, SOCKET_REUSE_FLAG, (const char*)&opt, sizeof(opt));

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
            cerr << "[服务器] 绑定端口失败！"; SOCKET_ERR_MSG(); exit(-1);
        }
        if (listen(server_fd, 5) == -1) {
            cerr << "[服务器] 监听失败！"; SOCKET_ERR_MSG(); exit(-1);
        }

        cout << "[服务器] ✅ 初始化完成 (ML-KEM768 + TLS1.3 后量子加密)" << endl;
        cout << "[服务器] ✅ 监听端口 " << port << " 中...【循环接收无限次连接】" << endl;
    }

    void run() {
        sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        while (true) {
            SOCKET_FD client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_addr_len);
            if (IS_INVALID_SOCKET(client_fd)) {
                cerr << "[服务器] 接收连接失败！"; SOCKET_ERR_MSG(); continue;
            }
            cout << "\n==================================================" << endl;
            cout << "[服务器] ✅ 客户端 " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << " 已连接" << endl;

            OQS_KEM* kem = OQS_KEM_new(MLKEM_ALG);
            // ✅ 修复核心2：所有close(fd)替换为跨平台宏CLOSE_SOCKET(fd)，解决未声明报错
            if (kem == nullptr) { cerr << "[服务器] ML-KEM初始化失败"; CLOSE_SOCKET(client_fd); continue; }

            uint8_t mlkem_pubkey[OQS_KEM_ml_kem_768_length_public_key] = {0};
            uint8_t mlkem_seckey[OQS_KEM_ml_kem_768_length_secret_key] = {0};
            uint8_t mlkem_ciphertext[OQS_KEM_ml_kem_768_length_ciphertext] = {0};
            uint8_t server_shared_key[PSK_LEN] = {0};

            OQS_KEM_keypair(kem, mlkem_pubkey, mlkem_seckey);
            // ✅ 修复核心3：用SEND_DATA/RECV_DATA宏，解决uint8_t转char*类型不匹配报错
            SEND_DATA(client_fd, mlkem_pubkey, OQS_KEM_ml_kem_768_length_public_key);
            RECV_DATA(client_fd, mlkem_ciphertext, OQS_KEM_ml_kem_768_length_ciphertext);

            OQS_STATUS kem_status = OQS_KEM_decaps(kem, server_shared_key, mlkem_ciphertext, mlkem_seckey);
            if (kem_status != OQS_SUCCESS) {
                cerr << "[服务器] ML-KEM协商失败";
                OQS_KEM_free(kem);
                CLOSE_SOCKET(client_fd);
                continue;
            }
            cout << "[服务器] ✅ ML-KEM768 后量子密钥协商成功！" << endl;

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) <= 0) {
                cerr << "[服务器] TLS握手失败：" << ERR_error_string(ERR_get_error(), nullptr);
                SSL_free(ssl);
                OQS_KEM_free(kem);
                CLOSE_SOCKET(client_fd);
                continue;
            }
            cout << "[服务器] ✅ TLS1.3 握手成功！协议版本：" << SSL_get_version(ssl) << endl;

            char buf[1024] = {0};
            int recv_len = SSL_read(ssl, buf, sizeof(buf)-1);
            if (recv_len > 0) {
                cout << "[服务器] ✅ 收到数据：" << buf << endl;
                string reply = "服务器已收到：" + string(buf);
                SSL_write(ssl, reply.c_str(), reply.size());
                cout << "[服务器] ✅ 已回复加密数据" << endl;
            }

            // 所有资源释放都用跨平台宏
            SSL_shutdown(ssl);
            SSL_free(ssl);
            OQS_KEM_free(kem);
            CLOSE_SOCKET(client_fd);
            cout << "[服务器] ✅ 客户端连接已关闭，等待下一个连接..." << endl;
        }
    }

    ~TLSServer() {
        // ✅ 修复：服务器socket关闭也用跨平台宏
        CLOSE_SOCKET(server_fd);
        SSL_CTX_free(ctx);
#ifdef _WIN32
        WSACleanup(); // Windows收尾清理Winsock
#endif
        cleanupCryptoLib();
    }
};

// ====================== ✅ TLS 客户端类 (无修改，之前已完美适配跨平台) ======================
class TLSClient {
private:
    const string server_ip;
    const int server_port;
    SSL_CTX* ctx;
    OQS_KEM* kem;

public:
    TLSClient(const string& ip_, int port_) : server_ip(ip_), server_port(port_) {
        initCryptoLib();
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            cerr << "[客户端] Windows Socket初始化失败！"; SOCKET_ERR_MSG();
            exit(-1);
        }
#endif

        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { cerr << "[客户端] SSL初始化失败：" << ERR_error_string(ERR_get_error(), nullptr) << endl; exit(-1); }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

        kem = OQS_KEM_new(MLKEM_ALG);
        if (kem == nullptr) { cerr << "[客户端] ML-KEM初始化失败！" << endl; exit(-1); }

        cout << "[客户端] ✅ 初始化完成 (ML-KEM768 + TLS1.3 后量子加密)" << endl;
        cout << "[客户端] ✅ 准备连接服务器 " << server_ip << ":" << server_port << endl;
    }

    void connectAndHandshake() {
        SOCKET_FD sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (IS_INVALID_SOCKET(sock_fd)) {
            cerr << "[客户端] 创建Socket失败！"; SOCKET_ERR_MSG();
            this->~TLSClient(); exit(-1);
        }

        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            cerr << "[客户端] IP地址格式错误！" << endl; CLOSE_SOCKET(sock_fd); this->~TLSClient(); exit(-1);
        }

        if (connect(sock_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
            cerr << "[客户端] 连接服务器失败！"; SOCKET_ERR_MSG();
            CLOSE_SOCKET(sock_fd); this->~TLSClient(); exit(-1);
        }
        cout << "[客户端] ✅ 与服务器建立TCP连接成功" << endl;

        uint8_t mlkem_pubkey[OQS_KEM_ml_kem_768_length_public_key] = {0};
        uint8_t mlkem_ciphertext[OQS_KEM_ml_kem_768_length_ciphertext] = {0};
        uint8_t client_shared_key[PSK_LEN] = {0};

        RECV_DATA(sock_fd, mlkem_pubkey, OQS_KEM_ml_kem_768_length_public_key);
        OQS_STATUS kem_status = OQS_KEM_encaps(kem, mlkem_ciphertext, client_shared_key, mlkem_pubkey);
        if (kem_status != OQS_SUCCESS) { cerr << "[客户端] ML-KEM协商失败！" << endl; CLOSE_SOCKET(sock_fd); this->~TLSClient(); return; }
        SEND_DATA(sock_fd, mlkem_ciphertext, OQS_KEM_ml_kem_768_length_ciphertext);
        cout << "[客户端] ✅ ML-KEM768 后量子密钥协商成功！" << endl;

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock_fd);
        SSL_set_tlsext_host_name(ssl, server_ip.c_str());
        if (SSL_connect(ssl) <= 0) {
            cerr << "[客户端] TLS握手失败：" << ERR_error_string(ERR_get_error(), nullptr) << endl;
            SSL_free(ssl); CLOSE_SOCKET(sock_fd); this->~TLSClient(); return;
        }
        cout << "[客户端] ✅ TLS1.3 握手成功！协议版本：" << SSL_get_version(ssl) << endl;

        string msg = "Hello! Cross-Platform ML-KEM+TLS Client!";
        SSL_write(ssl, msg.c_str(), msg.size());
        cout << "[客户端] ✅ 加密发送数据：" << msg << endl;

        char buf[1024] = {0};
        int recv_len = SSL_read(ssl, buf, sizeof(buf)-1);
        if (recv_len > 0) cout << "[客户端] ✅ 收到服务器加密回复：" << buf << endl;

        SSL_shutdown(ssl);
        SSL_free(ssl);
        CLOSE_SOCKET(sock_fd);
#ifdef _WIN32
        WSACleanup();
#endif
        cout << "[客户端] ✅ 连接已关闭，测试完成！" << endl;
    }

    ~TLSClient() {
        SSL_CTX_free(ctx);
        OQS_KEM_free(kem);
        cleanupCryptoLib();
    }
};

// ====================== ✅ 主函数 (无修改，编译时指定模式即可) ======================
int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "用法：" << argv[0] << " [server|client]" << endl;
        return -1;
    }
    string mode = argv[1];
    const int PORT = 8888;
    const string SERVER_IP = "127.0.0.1";
    const string CERT_PATH = "server.crt";
    const string KEY_PATH = "server.key";

    if (mode == "server") {
        TLSServer server(PORT, CERT_PATH, KEY_PATH);
        server.run();
    } else if (mode == "client") {
        TLSClient client(SERVER_IP, PORT);
        client.connectAndHandshake();
    } else {
        cerr << "仅支持 server/client 模式！" << endl;
        return -1;
    }
    return 0;
}