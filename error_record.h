#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define handle_error(cmd, result) \
    if (result < 0)               \
    {                             \
        perror(cmd);              \
        return -1;                \
    }

struct auth_header {
    uint8_t  op_type;    // 操作类型：0xA1=认证请求，0xA2=认证响应
    uint8_t  result;     // 认证结果：0=成功，1=失败，2=需要重试
    uint16_t data_len;   // 后续数据长度（网络字节序）
    uint32_t reserved;   // 保留字段
};
// 日志级别定义
typedef enum { INFO, WARN, ERROR } LogLevel;

// 日志记录函数
void log_message(LogLevel level, const char *message) {
    FILE *log_file = fopen("client_log.txt", "a");  // 打开日志文件（以追加模式）
    if (log_file == NULL) {
        perror("无法打开日志文件");
        return;
    }

    // 获取当前时间
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    
    // 格式化时间戳
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 根据日志级别选择不同的前缀
    const char *level_str = "";
    switch (level) {
        case INFO: level_str = "INFO"; break;
        case WARN: level_str = "WARN"; break;
        case ERROR: level_str = "ERROR"; break;
    }
    
    // 写入日志文件
    fprintf(log_file, "[%s] [%s] %s\n", time_str, level_str, message);
    
    fclose(log_file);  // 关闭文件
}




/*
 * 函数：encrypt_message
 * 说明  : 对输入的明文进行 AES-256-CBC 加密
 * 参数  :
 *    plaintext      - 待加密的明文数据
 *    plaintext_len  - 明文长度
 *    key            - 密钥（32字节，适用于 AES-256）
 *    iv             - 初始化向量（16字节）
 *    ciphertext     - 加密后数据存储的缓冲区，调用者需要保证有足够空间
 * 返回  : 加密后数据的字节数，若出错返回 -1
 */
int encrypt_message(const unsigned char *plaintext, int plaintext_len, 
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "无法创建加密上下文\n");
        return -1;
    }

    // 初始化加密操作，选择 AES-256-CBC 算法
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        fprintf(stderr, "EVP_EncryptInit_ex 初始化失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx,1);
    int len = 0;
    int ciphertext_len = 0;
    
    // 对数据进行加密，输出部分密文
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        fprintf(stderr, "EVP_EncryptUpdate 加密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    // 完成最后的加密操作
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        fprintf(stderr, "EVP_EncryptFinal_ex 加密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/*
 * 函数：decrypt_message
 * 说明  : 对输入的密文进行 AES-256-CBC 解密
 * 参数  :
 *    ciphertext     - 待解密的密文数据
 *    ciphertext_len - 密文长度
 *    key            - 密钥（32字节）
 *    iv             - 初始化向量（16字节）
 *    plaintext      - 解密后数据存储的缓冲区
 * 返回  : 解密后数据的字节数，若出错返回 -1
 */
int decrypt_message(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "无法创建解密上下文\n");
        return -1;
    }

    // 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        fprintf(stderr, "EVP_DecryptInit_ex 初始化失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx,1);
    int len = 0;
    int plaintext_len = 0;
    
    // 执行解密操作
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        fprintf(stderr, "EVP_DecryptUpdate 解密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    // 完成解密操作
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        fprintf(stderr, "EVP_DecryptFinal_ex 解密失败\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

    // 定义密钥和初始化向量，注意在实际应用中应使用安全的随机数
    unsigned char key[32] = "01234567890123456789012345678901";  // 32字节密钥
    unsigned char iv[16] = "0123456789012345";                    // 16字节初始化向量

