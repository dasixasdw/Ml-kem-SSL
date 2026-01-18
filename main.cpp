#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/kem.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

// 选择 ML-KEM 算法（可选：ml_kem_512/ml_kem_768/ml_kem_1024）
#define ML_KEM_ALG OQS_KEM_alg_ml_kem_768
// AES-GCM 密钥长度（ML-KEM 输出的会话密钥为 32 字节，适配 AES-256）
#define AES_KEY_LEN 32
// AES-GCM 随机数（IV）长度
#define AES_IV_LEN 12
// AES-GCM 标签长度（认证用）
#define AES_TAG_LEN 16

/**
 * @brief ML-KEM 加密函数（明文 -> 密文 + 会话密钥）
 * @param plaintext 输入：明文数据
 * @param plaintext_len 输入：明文长度（字节）
 * @param pk 输入：ML-KEM 公钥（由密钥对生成函数产出）
 * @param ciphertext 输出：最终密文（格式：KEM密文 + AES IV + AES密文 + AES标签）
 * @param ciphertext_len 输出：最终密文总长度
 * @param ss 输出：ML-KEM 会话密钥（可选，NULL 则内部使用）
 * @return 0 成功，非 0 失败
 */
int ml_kem_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *pk, uint8_t **ciphertext, size_t *ciphertext_len,
                   uint8_t *ss) {
    // 1. 初始化 OQS KEM 上下文
    OQS_KEM *kem = OQS_KEM_new(ML_KEM_ALG);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM context\n");
        return -1;
    }

    // 2. 分配内存：KEM 密文缓冲区（修复：ciphertext_length → length_ciphertext + C++ 强制类型转换）
    uint8_t *kem_ct = (uint8_t*)malloc(kem->length_ciphertext);
    if (kem_ct == NULL) {
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to malloc kem_ct\n");
        return -2;
    }

    // 3. 生成 ML-KEM 会话密钥和密文（封装）（修复：OQS_KEM_encapsulate → OQS_KEM_encaps）
    uint8_t local_ss[AES_KEY_LEN] = {0};
    if (OQS_KEM_encaps(kem, kem_ct, (ss == NULL) ? local_ss : ss, pk) != OQS_SUCCESS) {
        free(kem_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "KEM encapsulate failed\n");
        return -3;
    }
    const uint8_t *use_ss = (ss == NULL) ? local_ss : ss;

    // 4. AES-GCM 加密明文（使用 KEM 会话密钥）
    uint8_t iv[AES_IV_LEN];
    uint8_t tag[AES_TAG_LEN];
    // 修复：C++ 中 malloc 返回 void* 需强制转换为 uint8_t*
    uint8_t *aes_ct = (uint8_t*)malloc(plaintext_len); // AES 密文长度 = 明文长度（GCM 无膨胀）
    if (aes_ct == NULL) {
        free(kem_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to malloc aes_ct\n");
        return -4;
    }

    // 生成随机 IV
    OQS_randombytes(iv, AES_IV_LEN);

    // 初始化 AES-GCM 上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to create EVP context\n");
        return -5;
    }

    // 初始化加密操作
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, use_ss, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP EncryptInit failed\n");
        return -6;
    }

    // 执行 AES-GCM 加密
    int aes_ct_len = 0;
    if (EVP_EncryptUpdate(ctx, aes_ct, &aes_ct_len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP EncryptUpdate failed\n");
        return -7;
    }

    // 生成认证标签
    int tag_len = AES_TAG_LEN;
    if (EVP_EncryptFinal_ex(ctx, aes_ct + aes_ct_len, &tag_len) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP EncryptFinal failed\n");
        return -8;
    }
    EVP_CIPHER_CTX_free(ctx);

    // 5. 拼接最终密文：KEM密文 + IV + AES密文 + 标签（修复：ciphertext_length → length_ciphertext）
    *ciphertext_len = kem->length_ciphertext + AES_IV_LEN + plaintext_len + AES_TAG_LEN;
    // 修复：C++ 中 malloc 返回 void* 需强制转换
    *ciphertext = (uint8_t*)malloc(*ciphertext_len);
    if (*ciphertext == NULL) {
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to malloc final ciphertext\n");
        return -9;
    }

    size_t offset = 0;
    memcpy(*ciphertext + offset, kem_ct, kem->length_ciphertext);
    offset += kem->length_ciphertext;
    memcpy(*ciphertext + offset, iv, AES_IV_LEN);
    offset += AES_IV_LEN;
    memcpy(*ciphertext + offset, aes_ct, plaintext_len);
    offset += plaintext_len;
    memcpy(*ciphertext + offset, tag, AES_TAG_LEN);

    // 6. 清理临时内存
    free(kem_ct);
    free(aes_ct);
    OQS_KEM_free(kem);

    return 0;
}

/**
 * @brief ML-KEM 解密函数（密文 + 私钥 -> 明文）
 * @param ciphertext 输入：加密函数产出的最终密文
 * @param ciphertext_len 输入：最终密文长度
 * @param sk 输入：ML-KEM 私钥（由密钥对生成函数产出）
 * @param plaintext 输出：解密后的明文
 * @param plaintext_len 输出：明文长度
 * @return 0 成功，非 0 失败
 */
int ml_kem_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *sk, uint8_t **plaintext, size_t *plaintext_len) {
    // 1. 初始化 OQS KEM 上下文
    OQS_KEM *kem = OQS_KEM_new(ML_KEM_ALG);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM context\n");
        return -1;
    }

    // 2. 校验密文长度合法性（修复：ciphertext_length → length_ciphertext）
    size_t min_ciphertext_len = kem->length_ciphertext + AES_IV_LEN + AES_TAG_LEN;
    if (ciphertext_len < min_ciphertext_len) {
        OQS_KEM_free(kem);
        fprintf(stderr, "Invalid ciphertext length\n");
        return -2;
    }

    // 3. 拆分密文：KEM密文 + IV + AES密文 + 标签（修复：ciphertext_length → length_ciphertext + 强制类型转换）
    size_t offset = 0;
    uint8_t *kem_ct = (uint8_t*)malloc(kem->length_ciphertext);
    memcpy(kem_ct, ciphertext + offset, kem->length_ciphertext);
    offset += kem->length_ciphertext;

    uint8_t iv[AES_IV_LEN];
    memcpy(iv, ciphertext + offset, AES_IV_LEN);
    offset += AES_IV_LEN;

    *plaintext_len = ciphertext_len - offset - AES_TAG_LEN; // 明文长度 = 剩余长度 - 标签长度
    // 修复：C++ 中 malloc 返回 void* 需强制转换
    uint8_t *aes_ct = (uint8_t*)malloc(*plaintext_len);
    memcpy(aes_ct, ciphertext + offset, *plaintext_len);
    offset += *plaintext_len;

    uint8_t tag[AES_TAG_LEN];
    memcpy(tag, ciphertext + offset, AES_TAG_LEN);

    // 4. ML-KEM 解封装恢复会话密钥（修复：OQS_KEM_decapsulate → OQS_KEM_decaps）
    uint8_t ss[AES_KEY_LEN] = {0};
    if (OQS_KEM_decaps(kem, ss, kem_ct, sk) != OQS_SUCCESS) {
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "KEM decapsulate failed\n");
        return -3;
    }

    // 5. AES-GCM 解密（验证标签 + 恢复明文）
    // 修复：C++ 中 malloc 返回 void* 需强制转换
    *plaintext = (uint8_t*)malloc(*plaintext_len);
    if (*plaintext == NULL) {
        free(kem_ct);
        free(aes_ct);
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to malloc plaintext\n");
        return -4;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(kem_ct);
        free(aes_ct);
        free(*plaintext);
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to create EVP context\n");
        return -5;
    }

    // 初始化解密操作
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        free(*plaintext);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP DecryptInit failed\n");
        return -6;
    }

    // 执行 AES-GCM 解密
    int plaintext_tmp_len = 0;
    if (EVP_DecryptUpdate(ctx, *plaintext, &plaintext_tmp_len, aes_ct, *plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        free(*plaintext);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP DecryptUpdate failed\n");
        return -7;
    }

    // 设置并验证标签（防篡改）
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        free(*plaintext);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP set tag failed\n");
        return -8;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, *plaintext + plaintext_tmp_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(kem_ct);
        free(aes_ct);
        free(*plaintext);
        OQS_KEM_free(kem);
        fprintf(stderr, "EVP DecryptFinal failed (tag verify failed)\n");
        return -9;
    }
    *plaintext_len = plaintext_tmp_len + final_len;
    EVP_CIPHER_CTX_free(ctx);

    // 6. 清理临时内存
    free(kem_ct);
    free(aes_ct);
    OQS_KEM_free(kem);

    return 0;
}

// 辅助函数：生成 ML-KEM 密钥对
int ml_kem_keygen(uint8_t **pk, uint8_t **sk) {
    OQS_KEM *kem = OQS_KEM_new(ML_KEM_ALG);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM context\n");
        return -1;
    }

    // 修复：public_key_length → length_public_key / secret_key_length → length_secret_key + 强制类型转换
    *pk = (uint8_t*)malloc(kem->length_public_key);
    *sk = (uint8_t*)malloc(kem->length_secret_key);
    if (*pk == NULL || *sk == NULL) {
        free(*pk);
        free(*sk);
        OQS_KEM_free(kem);
        fprintf(stderr, "Failed to malloc key pair\n");
        return -2;
    }

    if (OQS_KEM_keypair(kem, *pk, *sk) != OQS_SUCCESS) {
        free(*pk);
        free(*sk);
        OQS_KEM_free(kem);
        fprintf(stderr, "KEM keypair failed\n");
        return -3;
    }

    OQS_KEM_free(kem);
    return 0;
}

// 测试示例
int main() {
    // 1. 初始化 OQS（修复：OQS_init() 返回 void，无需判断返回值）
    OQS_init();

    // 2. 生成 ML-KEM 密钥对
    uint8_t *pk = NULL, *sk = NULL;
    if (ml_kem_keygen(&pk, &sk) != 0) {
        return -1;
    }

    // 3. 待加密的明文
    const char *msg = "你好，我的世界";
    size_t msg_len = strlen(msg);

    // 4. 加密
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t ss[AES_KEY_LEN] = {0}; // 会话密钥（可选保存）
    if (ml_kem_encrypt((uint8_t *)msg, msg_len, pk, &ciphertext, &ciphertext_len, ss) != 0) {
        free(pk);
        free(sk);
        return -1;
    }
    printf("Encrypt success, ciphertext length: %zu\n", ciphertext_len);

    // 5. 解密
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    if (ml_kem_decrypt(ciphertext, ciphertext_len, sk, &decrypted, &decrypted_len) != 0) {
        free(pk);
        free(sk);
        free(ciphertext);
        return -1;
    }
    printf("Decrypt success, plaintext: %.*s\n", (int)decrypted_len, decrypted);

    // 6. 清理内存（修复：OQS_cleanup() → OQS_destroy()）
    free(pk);
    free(sk);
    free(ciphertext);
    free(decrypted);
    OQS_destroy();

    return 0;
}