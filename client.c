#include "error_record.h"


#define MAX_LEN 256


void *read_from_server(void *argv)
{
    int sockfd = *(int *)argv;
    char *read_buf = NULL;
    ssize_t count = 0;

    read_buf = malloc(sizeof(char) * 1024);
    if (!read_buf)
    {
        perror("malloc client read_buf");
        return NULL;
    }

    while ((count = recv(sockfd, read_buf, 1024, 0)) > 0)
    {
        fputs(read_buf, stdout);
    }
    if (count < 0)
    {
        perror("recv");
    }


    printf("收到服务端的终止信号......\n");
    free(read_buf);

    return NULL;
}

void *write_to_server(void *argv)
{
    int sockfd = *(int *)argv;
    char *write_buf = NULL;
    ssize_t send_count;

    write_buf = malloc(sizeof(char) * 1024);

    if (!write_buf)
    {
        printf("写缓存申请异常，断开连接\n");
        shutdown(sockfd, SHUT_WR);
        perror("malloc client write_buf");
        return NULL;
    }

    while (fgets(write_buf, 1024, stdin) != NULL)
    {
        // 为密文分配内存，长度至少为明文长度加上一个块大小（16字节）
        unsigned char *ciphertext = malloc(strlen(write_buf) + 16);
        if (!ciphertext)
        {
            perror("ciphertext");
        }
        // 执行加密
       int ciphertext_len = encrypt_message((unsigned char *)write_buf, strlen(write_buf), key, iv, ciphertext);
       if (ciphertext_len < 0)
       {
            perror("encrypt_message");
            free(ciphertext);
            continue;
       }
        // 发送加密后的消息
        send_count=send(sockfd, ciphertext, ciphertext_len, 0);
        if (send_count < 0)
        {
            perror("send");
        }
        free(ciphertext);
        
    }
    
    printf("接收到命令行的终止信号，不再写入，关闭连接......\n");
    shutdown(sockfd, SHUT_WR);
    free(write_buf);

    return NULL;
}

int auth_server(int sockfd) {
    
    char username[MAX_LEN];  // 正确：字符数组
    char password[MAX_LEN];
    
    // 获取用户输入
    printf("帐号： ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0; // 去掉换行符
    
    printf("密码: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    
    // 计算密码哈希（需实现sha256函数）
    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, password, strlen(password));
    SHA256_Final(hashed_password, &sha256_ctx);

    // 将哈希值转换为十六进制字符串
    char hashed_password_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hashed_password_hex[i * 2], "%02x", hashed_password[i]);
    }
    
    // 使用 cJSON 创建 JSON 对象
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddStringToObject(root, "password", hashed_password_hex);
    char *json_str = cJSON_PrintUnformatted(root);
    
    // 发送认证头
    struct auth_header header = {
        .op_type = 0xA1,
        .result = 0,
        .data_len = htons(strlen(json_str)),
        .reserved = 0
    };
    send(sockfd, &header, sizeof(header), 0);
    send(sockfd, json_str, strlen(json_str), 0);
    
    // 等待响应
    struct auth_header resp_header;
    recv(sockfd, &resp_header, sizeof(resp_header), 0);
    if (resp_header.op_type != 0xA2) {
        fprintf(stderr, "Protocol error\n");
        return 1;
    }
    
    char resp_msg[256];
    recv(sockfd, resp_msg, ntohs(resp_header.data_len), 0);
    resp_msg[ntohs(resp_header.data_len)] = 0;
    
    if (resp_header.result != 0) {
        fprintf(stderr, "Authentication failed: %s\n", resp_msg);
        return 1;
    }
    
    printf("认证成功\n");
    return 0;
}

int main(int argc, char const *argv[])
{
    
    int sockfd, temp_result;
    pthread_t pid_read, pid_write;

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    // 连接本机 127.0.0.1
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // 连接端口 6666
    server_addr.sin_port = htons(6666);

    // 创建socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    handle_error("socket", sockfd);

    // 连接server
    temp_result = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    handle_error("connect", temp_result);

    // 认证server
    if(auth_server(sockfd)){
        return 0;
    }

    // 启动一个子线程，用来读取服务端数据，并打印到 stdout
    pthread_create(&pid_read, NULL, read_from_server, (void *)&sockfd);
    // 启动一个子线程，用来从命令行读取数据并发送到服务端
    pthread_create(&pid_write, NULL, write_to_server, (void *)&sockfd);

    // 主线程等待子线程退出
    pthread_join(pid_read, NULL);
    pthread_join(pid_write, NULL);

    log_message(INFO, "退出当前子线程");
    printf("关闭资源\n");
    close(sockfd);

    return 0;
}