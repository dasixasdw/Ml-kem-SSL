/**
* @file crypto_utils.h
 * @brief ML-KEM Post Quantum Cryptography Project - Cryptography Utilities Header File
 * @brief ML-KEM抗量子密码学项目 密码学工具类头文件
 * @details Declare the core cryptography tool function interface, encapsulate liboqs post-quantum library and OpenSSL TLS library initialization, resource release and SSL context creation functions.
 * @details 声明项目核心密码学工具函数接口，封装liboqs抗量子库、OpenSSL TLS库的初始化、资源释放及SSL加密上下文创建功能。
 * @date 2026/01/19
 */

#ifndef MLKEM_CRYPTO_UTILS_H
#define MLKEM_CRYPTO_UTILS_H

#include <string>
#include <openssl/ssl.h>

/**
 * @brief Initialize the dependent cryptography libraries
 * 初始化项目依赖的所有密码学库
 * @details Execute the standard initialization process for liboqs post-quantum cryptography library and OpenSSL TLS encryption library
 * 对liboqs抗量子密码库、OpenSSL TLS加密库执行标准初始化流程
 */
void initCryptoLib();

/**
 * @brief Release all resources occupied by the cryptography libraries
 * 清理并释放密码学库占用的所有系统资源
 * @details Standard resource cleanup operation for OpenSSL library, prevent memory leaks and resource occupation
 * 对OpenSSL库执行标准资源清理操作，防止内存泄漏与系统资源占用
 */
void cleanCryptoLib();

/**
 * @brief Create and configure SSL/TLS encryption communication context
 * 创建并完成SSL/TLS加密通信上下文的初始化配置
 * @param is_server Identity mark, true means server side, false means client side
 *        角色标识，true表示服务端，false表示客户端
 * @param cert_path File path of TLS certificate in PEM format, default empty string
 *        PEM格式的TLS证书文件路径，默认空字符串
 * @param key_path File path of TLS private key in PEM format, default empty string
 *        PEM格式的TLS私钥文件路径，默认空字符串
 * @return Valid SSL_CTX pointer for successful creation, exit the program directly if failed
 *         创建成功返回有效SSL_CTX上下文指针，创建失败则直接退出程序
 */
SSL_CTX* createSSLContext(bool is_server, const std::string& cert_path = "", const std::string& key_path = "");

#endif // MLKEM_CRYPTO_UTILS_H