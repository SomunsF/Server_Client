# CC:=gcc
#  $@相当于当前target目标文件的名称，此处为main。
#  $^相当于当前target所有依赖文件列表，此处为main.c
#  ./$@的作用是执行目标文件
#  rm ./$@的作用是在执行完毕后删除目标文件，如果没有这个操作，当源文为main.c未更改时就无法重复执行，会提示：make：为main”已是最新。此处删除目标文件，使得我们在不更改源文件的情况下可以多次执行。
# 5: 5.c
# 	-$(CC) -o $@ $^
# 	-./$@
# 	-rm ./$@
# xianchengpool: xianchengpool.c
# 	-$(CC) -o $@ $^ `pkg-config --cflags --libs glib-2.0`
# 	-./$@
# 	-rm ./$@
# fuwuduan: fuwuduan.c
# 	-$(CC) -o $@ $^

# 编译器和标志123
CC = gcc
CFLAGS = -lpthread -lssl -lcrypto

# 目标
TARGETS = server client

# 默认目标
all: $(TARGETS)

# 编译 server 和 client
server: server.c
	gcc server.c -o server -lpthread -lssl -lcrypto -lcjson

client: client.c
	gcc client.c -o client -lpthread -lssl -lcrypto -lcjson

run_server:
	./server

run_client:
	./client

# 清理
clean: