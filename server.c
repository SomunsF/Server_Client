#include "error_record.h"

#define MAX_USERNAME_LEN 50
#define SHA256_HASH_LEN 64
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


/// 用户凭证结构体
typedef struct {
    char username[MAX_USERNAME_LEN];  // 用户名
    char password_hash[SHA256_HASH_LEN + 1];  // SHA-256哈希值（+1用于存储 '\0' 终止符）
} UserCredential;

// 示例用户凭证
UserCredential valid_users[] = {
    {"admin", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"},  // password="123456"
    {"guest", "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a"}   // password="111111"
};

// 凭证验证函数
bool check_credentials(const char *username, const char *input_hash) {
    for (int i = 0; i < sizeof(valid_users)/sizeof(valid_users); i++) {
        if (strcmp(valid_users[i].username, username) == 0) {
            return (strcmp(valid_users[i].password_hash, input_hash) == 0);
        }
    }
    return false;
}

// 发送认证响应
void send_auth_response(int fd, uint8_t result, const char *message) {
    struct auth_header resp_header = {
        .op_type = 0xA2,
        .result = result,
        .data_len = htons(strlen(message)),
        .reserved = 0
    };
    
    send(fd, &resp_header, sizeof(resp_header), 0);
    send(fd, message, strlen(message), 0);
}

// 认证
int handle_client(int client_fd) {
    struct auth_header header;
    char buffer[1024];
    int auth_attempts = 0;
    bool authenticated = false;

    // 认证阶段（最多尝试3次）
    while (auth_attempts < 3 && !authenticated) {
        // 接收认证头
        if (recv(client_fd, &header, sizeof(header), 0) <= 0) {
            perror("recv header failed");
            break;
        }

        // 验证协议类型
        if (header.op_type != 0xA1 || ntohs(header.data_len) > sizeof(buffer)) {
            send_auth_response(client_fd, 1, "Invalid protocol");
            break;
        }

        // 接收认证数据
        int bytes_received = recv(client_fd, buffer, ntohs(header.data_len), 0);
        if (bytes_received <= 0) break;

        // 解析JSON（需引入cJSON库）
        cJSON *root = cJSON_Parse(buffer);
        char *username = cJSON_GetObjectItem(root, "username")->valuestring;
        char *password_hash = cJSON_GetObjectItem(root, "password")->valuestring;

        // 验证凭证
        authenticated = check_credentials(username, password_hash);
        
        // 发送响应
        if (authenticated) {
            send_auth_response(client_fd, 0, "Auth success");
        } else {
            send_auth_response(client_fd, 1, "Invalid credentials");
            auth_attempts++;
        }

        cJSON_Delete(root);
    }

    if (!authenticated) {
        close(client_fd);
        return 1;
    }else return 0;

    
}

void *read_from_client(void *argv)
{
    int client_fd = *(int *)argv;
    ssize_t count = 0, send_count = 0;
    char *read_buf = malloc(sizeof(char) * 1024);
    char *write_buf = malloc(sizeof(char) * 1024);

    if (!read_buf)
    {
        printf("服务端读缓存创建异常，断开连接\n");
        shutdown(client_fd, SHUT_WR);
        close(client_fd);
        perror("malloc server read_buf");
        return NULL;
    }

    if (!write_buf)
    {
        printf("服务端写缓存创建异常，断开连接\n");
        free(read_buf);
        shutdown(client_fd, SHUT_WR);
        close(client_fd);
        perror("malloc server write_buf");
        return NULL;
    }

    while ((count = recv(client_fd, read_buf, 1024, 0)) > 0)
    {
        // 分配解密后明文内存
        unsigned char *decryptedtext = malloc(1025);
        if (!decryptedtext)
        {
            perror("malloc decryptedtext failed");
            break;
        }
        // 解密数据并存到decryptedtext
        int decryptedtext_len = decrypt_message((unsigned char *)read_buf, count, key, iv, decryptedtext);
        if (decryptedtext_len < 0)
        {
            perror("decrypt_message");
            free(decryptedtext);
            continue;
        }
        decryptedtext[decryptedtext_len] = '\0';
        printf("收到消息：%s 来自客户端client_fd:%d\n", decryptedtext, client_fd);
        free(decryptedtext);

        strcpy(write_buf, "服务器已收到\n");
        send_count = send(client_fd, write_buf, strlen(write_buf), 0);
        if (send_count < 0)
        {
            perror("send");
        }
        
    }

    if (count < 0)
        perror("recv");

    printf("客户端client_fd: %d请求关闭连接......\n", client_fd);
    strcpy(write_buf, "收到关闭信息\n");

    send_count = send(client_fd, write_buf, strlen(write_buf), 0);
    if (send_count < 0)
    {
        perror("send");
    }
    
    printf("释放client_fd: %d资源\n", client_fd);
    shutdown(client_fd, SHUT_WR);
    close(client_fd);
    free(read_buf);
    free(write_buf);

    return NULL;
}

// void *write_to_client(void *argv){
//     while (1)
//     {
//     //加锁
//     pthread_mutex_lock(&mutex); 
//     int client_fd = *(int *)argv;
//     char *buf=malloc(1024);
//     //判断输入的客户号与当前线程客户号是否相同
//         if(*strcpy(buf,stdin)==client_fd){
//             char *send_buf=malloc(sizeof(char) * 1024);
//             printf("准备向client_fd：%d发消息，请输入要发送的内容",client_fd);
//             while (1)
//             {
//                 write(send_buf,stdin,strlen(stdin));
//                 send(client_fd,send_buf,strlen(send_buf),0);   
//                 printf("发送成功,如需对其它客户端发送消息请输入-1");
//                 char *b=malloc(4);
//                 getchar();
//                 if(*strcpy(b,stdin)==-1){
//                     pthread_mutex_unlock(&mutex); 
//                     free(buf);
//                     free(send_buf);
//                     return;
//                 }else continue;
//             }
//         }
//         else{
//         // 不相同，则解锁
//         pthread_mutex_unlock(&mutex); 
//         free(buf);
//         }
//     }
    
// }
// void *write_to_client(void *arg) {
//     int client_fd = *(int *)arg;
//     char buf[1024];

//     while (1) {
//         // 加锁获取用户输入，防止多个线程同时从标准输入读取数据
//         pthread_mutex_lock(&mutex);
//         printf("请输入目标客户端号: ");
//         if (fgets(buf, sizeof(buf), stdin) == NULL) {
//             printf("读取客户号失败，请重试。\n");
//             pthread_mutex_unlock(&mutex);
//             continue;
//         }
//         // 去除换行符
//         buf[strcspn(buf, "\n")] = '\0';
//         int input_client = atoi(buf);

//         // 判断输入的客户号是否与当前线程的客户端号相同
//         if (input_client == client_fd) {
//             char send_buf[1024];
//             printf("准备向 client_fd %d 发消息，请输入要发送的内容:\n", client_fd);
            
//             while (1) {
//                 // 读取要发送的消息
//                 if (fgets(send_buf, sizeof(send_buf), stdin) == NULL) {
//                     printf("读取消息失败，请重试。\n");
//                     continue;
//                 }
//                 // 去除消息末尾的换行符
//                 send_buf[strcspn(send_buf, "\n")] = '\0';

//                 // 发送消息给客户端
//                 if (send(client_fd, send_buf, strlen(send_buf), 0) == -1) {
//                     perror("send error");
//                 } else {
//                     printf("发送成功。\n");
//                 }
                
//                 // 询问是否退出当前发送模式
//                 printf("如需对其它客户端发送消息请输入 -1，否则继续输入消息：");
//                 if (fgets(buf, sizeof(buf), stdin) == NULL) {
//                     printf("读取选择失败，请重试。\n");
//                     continue;
//                 }
//                 buf[strcspn(buf, "\n")] = '\0';
//                 if (atoi(buf) == -1) {
//                     break;  // 跳出当前内层循环
//                 }
//             }
//         }
//         // 解锁后继续外层循环，等待下一个输入
//         pthread_mutex_unlock(&mutex);
//     }
//     return NULL;
// }
// 全局变量


// 单独的输入处理线程
void *handle_user_input(void *arg) {
    char buf[1024];
    char send_buf[1024];
    
    while (1) {
        printf("请输入目标客户端号: ");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            printf("读取客户号失败，请重试。\n");
            continue;
        }
        buf[strcspn(buf, "\n")] = '\0';
        int target_client = atoi(buf);
        
        // 查找目标客户端
        pthread_mutex_lock(&input_mutex);
        bool found = false;
        for (int i = 0; i < client_count; i++) {
            if (client_fds[i] == target_client) {
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&input_mutex);
        
        if (!found) {
            printf("客户端 %d 不存在或已断开连接\n", target_client);
            continue;
        }
        
        printf("准备向 client_fd %d 发消息，请输入要发送的内容:\n", target_client);
        while (1) {
            if (fgets(send_buf, sizeof(send_buf), stdin) == NULL) {
                printf("读取消息失败，请重试。\n");
                continue;
            }
            send_buf[strcspn(send_buf, "\n")] = '\0';
            
            if (send(target_client, send_buf, strlen(send_buf), 0) == -1) {
                perror("send error");
            } else {
                printf("发送成功。\n");
            }
            
            printf("如需对其它客户端发送消息请输入 -1，否则继续输入消息：");
            if (fgets(buf, sizeof(buf), stdin) == NULL) {
                printf("读取选择失败，请重试。\n");
                continue;
            }
            buf[strcspn(buf, "\n")] = '\0';
            if (atoi(buf) == -1) {
                break;
            }
        }
    }
    return NULL;
}



int main(int argc, char const *argv[])
{   
    
    int sockfd, temp_result;

    struct sockaddr_in server_addr, client_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    // 声明IPV4通信协议
    server_addr.sin_family = AF_INET;
    // 我们需要绑定0.0.0.0地址，转换成网络字节序后完成设置
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // 端口随便用一个，但是不要用特权端口
    server_addr.sin_port = htons(6666);

    // 创建server socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    handle_error("socket", sockfd);

    // 绑定地址
    temp_result = bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    handle_error("bind", temp_result);
    
    printf("等待客户端连接...\n");
    fflush(stdout);
    // 进入监听模式
    temp_result = listen(sockfd, 128);
    handle_error("listen", temp_result);

    socklen_t cliaddr_len = sizeof(client_addr);

    // 接受client连接
    while (1)
    {
        int client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &cliaddr_len);
        if(client_fd<0){
            log_message(ERROR, "连接失败");
            handle_error("accept", client_fd);
        }else{
            log_message(INFO, "连接成功");
        }

        if(handle_client(client_fd)){
            log_message(ERROR, "认证失败");
            continue;
        }else{
            log_message(INFO, "认证成功");
        };
        
        client_fds[client_count++]=client_fd;
        printf("与客户端 from %s at PORT %d 文件描述符 %d 建立连接\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_fd);

        pthread_t pid_read;
        pthread_t pid_write;
        // 在主程序中启动一个输入处理线程
        
        // 启动一个子线程，用来读取客户端数据，并打印到 stdout
        
        if (pthread_create(&pid_read, NULL, read_from_client, (void *)&client_fd))
        {
            perror("pthread_read_create");
        }
        
        if (pthread_create(&pid_write, NULL, handle_user_input, NULL))
        {
            perror("pthread_write_create");
        }
        // 将子线程处理为detached状态，使其终止时自动回收资源，同时不阻塞主线程
        pthread_detach(pid_read);
        pthread_detach(pid_write);
        printf("创建子线程并处理为detached状态\n");
        printf("如需指定客户端发送消息，请直接输入客户号\n");
    }

    printf("释放资源\n");
    //销毁锁
    pthread_mutex_destroy(&mutex);
    close(sockfd);

    return 0;
}
