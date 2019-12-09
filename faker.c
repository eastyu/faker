#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CONFIG_CLIENT_DEFAULT_TIMEOUT       (1800 * 1000)
#define CONFIG_LISTEN_BACKLOG               256
#define CONFIG_LOG_LEVEL                    LOG_LEVEL_DEBUG
#define CONFIG_RECV_BUFFER_SIZE             (4096 - sizeof(struct net_buffer))
#define CONFIG_SEND_BUFFER_SIZE             (4096 - sizeof(struct net_buffer))

#define EPOLL_EVENT_SIZE                    256

#define LOG_BUFFER_SIZE                     4096

#define NET_WORKER_STATUS_READY             0
#define NET_WORKER_STATUS_EXIT              1

#define NET_SERVER_STATUS_READY             0
#define NET_SERVER_STATUS_EXIT              1

#define NET_CLIENT_STATUS_CONNECTED         0

#define CLOSED_TIMEOUT                      0
#define CLOSED_ERROR                        1
#define CLOSED_EXIT                         2

#define NET_CLIENT_TYPE_UNKNOWN             0
#define NET_CLINET_TYPE_LOCAL_BROWSER       1
#define NET_CLIENT_TYPE_REMOTE_SERVER       2
#define NET_CLIENT_TYPE_CHANNEL_1           3
#define NET_CLIENT_TYPE_CHANNEL_2           4

#define LOG_LEVEL_DEBUG                     0
#define LOG_LEVEL_INFO                      1
#define LOG_LEVEL_WARN                      2
#define LOG_LEVEL_ERROR                     3

#define container_of(ptr, type, member)     \
    (type*)((NULL == (ptr)) ? NULL : (char*)(ptr) - offsetof(type, member))

#define log_debug(format, ...)              \
    write_log_to_file(LOG_LEVEL_DEBUG, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define log_info(format, ...)               \
    write_log_to_file(LOG_LEVEL_INFO, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define log_warn(format, ...)               \
    write_log_to_file(LOG_LEVEL_WARN, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define log_error(format, ...)              \
    write_log_to_file(LOG_LEVEL_ERROR, __FILE__, __LINE__, format, ##__VA_ARGS__)

struct list_item
{
    struct list_item* next;
    struct list_item* prev;
};

struct linked_list
{
    struct list_item* head;
    struct list_item* tail;
};

struct net_buffer
{
    char* data_ptr;
    int data_size;
    struct list_item __item;
};

struct net_client
{
    int client_socket;
    int expire_time;
    int registered_event;
    int client_status;
    int client_type;
    struct list_item __item;
    struct linked_list __send_list;
    struct linked_list __receive_list;
};

struct net_worker
{
    int worker_status;
    int epoll_handle;
    pthread_t worker_thread;
    struct list_item __item;
    struct linked_list __client_list;
};

struct net_server
{
    int listen_socket;
    int epoll_handle;
    int server_status;
    pthread_t server_thread;
    struct linked_list __worker_list;
};

int write_log_to_file(int level, const char* file, int line, const char* format, ...)
{
    if (level < CONFIG_LOG_LEVEL)
    {
        return 0;
    }

    struct timeval tv = { 0 };
    if (-1 == gettimeofday(&tv, NULL))
    {
        tv.tv_sec = time(NULL);
    }

    struct tm local_tm = { 0 };
    localtime_r(&tv.tv_sec, &local_tm);

    char buffer[LOG_BUFFER_SIZE] = { 0 };

    char const* prefix[] = { "DEBUG", "INFO", "WARN", "ERROR" };

    int length = sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d.%04ld [%s] file=%s line=%d ",
        local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday, local_tm.tm_hour,
        local_tm.tm_min, local_tm.tm_sec, tv.tv_usec / 1000, prefix[level % 4], file, line);

    va_list args; va_start(args, format); vsprintf(buffer + length, format, args); va_end(args);

    return (fprintf(stderr, "%s\n", buffer) > 0) ? 0 : -1;
}

int system_get_time()
{
    struct timeval tv = { 0 };
    if (-1 == gettimeofday(&tv, NULL))
    {
        return time(NULL) * 1000;
    }

    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int set_socket_to_nonblock(int socket)
{
    int flags = fcntl(socket, F_GETFL, 0);
    if (-1 == flags)
    {
        log_error("system call `fcntl` failed with error %d", errno);
    _e1:
        return -1;
    }

    if (-1 == fcntl(socket, F_SETFL, flags | O_NONBLOCK))
    {
        log_error("system call `fcntl` failed with error %d", errno);

        goto _e1;
    }

    return 0;
}

struct list_item* linked_list_get_item(struct linked_list* list)
{
    return list->head;
}

void linked_list_add_item(struct linked_list* list, struct list_item* item)
{
    item->prev = list->tail;
    item->next = NULL;

    if (NULL == list->head)
    {
        list->head = item;
    }

    if (NULL != list->tail)
    {
        list->tail->next = item;
    }

    list->tail = item;
}

void linked_list_remove_item(struct linked_list* list, struct list_item* item)
{
    struct list_item* prev = item->prev;
    struct list_item* next = item->next;

    if (NULL == next)
    {
        list->tail = prev;
    }
    else
    {
        next->prev = prev;
    }

    if (NULL == prev)
    {
        list->head = next;
    }
    else
    {
        prev->next = next;
    }

    item->prev = NULL;
    item->next = NULL;
}

struct net_buffer* net_buffer_create(int buffer_size)
{
    struct net_buffer* buffer = calloc(1, sizeof(struct net_buffer) + buffer_size);
    if (NULL == buffer)
    {
        log_error("system call `calloc` failed with error %d", errno);

        return NULL;
    }

    buffer->data_ptr = (char*)(buffer + 1);
    buffer->data_size = buffer_size;

    log_debug("buffer 0x%08X with size %d is created", buffer, buffer_size);

    return buffer;
}

void net_buffer_destroy(struct net_buffer* buffer)
{
    free(buffer);

    log_debug("buffer 0x%08X is destroyed", buffer);
}

int net_client_get_remaining_time(struct net_client* client)
{
    return client->expire_time - system_get_time();
}

void net_client_reset_expire_time(struct net_client* client)
{
    client->expire_time = system_get_time() + CONFIG_CLIENT_DEFAULT_TIMEOUT;
}

struct net_client* net_client_create(int client_socket, int client_type)
{
    struct net_client* client = calloc(1, sizeof(struct net_client));
    if (NULL == client)
    {
        log_error("system call `calloc` failed with error %d", errno);

        return NULL;
    }

    client->client_socket = client_socket;
    client->client_type = client_type;
    client->client_status = NET_CLIENT_STATUS_CONNECTED;

    net_client_reset_expire_time(client);

    log_debug("client 0x%08X with socket %d is created", client, client_socket);

    return client;
}

struct net_buffer* net_client_get_send_buffer(struct net_client* client)
{
    return container_of(linked_list_get_item(&client->__send_list), struct net_buffer, __item);
}

void net_client_remove_send_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_remove_item(&client->__send_list, &buffer->__item);
}

void net_client_add_send_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_add_item(&client->__send_list, &buffer->__item);
}

struct net_buffer* net_client_get_receive_buffer(struct net_client* client)
{
    return container_of(linked_list_get_item(&client->__receive_list), struct net_buffer, __item);
}

void net_client_remove_receive_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_remove_item(&client->__receive_list, &buffer->__item);
}

void net_client_add_receive_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_add_item(&client->__receive_list, &buffer->__item);
}

int net_client_send_data(struct net_client* client, struct net_worker* worker)
{
    struct epoll_event event = { 0 };
    event.data.ptr = client;
    event.events = EPOLLET | EPOLLIN;

    while (1)
    {
        struct net_buffer* buffer = net_client_get_send_buffer(client);
        if (NULL == buffer)
        {
            log_debug("no send buffer in the list");

            break;
        }

        while (buffer->data_size > 0)
        {
            int length = send(client->client_socket, buffer->data_ptr, buffer->data_size, 0);
            if (0 >= length)
            {
                if (-1 == length && EAGAIN == errno)
                {
                    log_debug("need to send again later");

                    event.events |= EPOLLOUT;
                    goto _end;
                }

                log_error("system call `send` failed with error %d", errno);
            _e1:
                return -1;
            }

            buffer->data_size -= length;
            buffer->data_ptr += length;
        }

        net_client_remove_send_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

_end:
    if (client->registered_event != event.events)
    {
        if (-1 == epoll_ctl(worker->epoll_handle, EPOLL_CTL_MOD, client->client_socket, &event))
        {
            log_error("system call `epoll_ctl` failed with error %d", errno);

            goto _e1;
        }

        client->registered_event = event.events;
    }

    return 0;
}

int net_client_send_hello_world_test(struct net_client* client, struct net_worker* worker)
{
    char* http_resonse = "HTTP/1.1 200 OK\r\n"
                         "Server: Faker/1.0\r\n"
                         "Content-Type: text/html; charset=utf-8\r\n"
                         "Content-Length: 11\r\n\r\n"
                         "hello world";
    struct net_buffer* buffer = net_buffer_create(CONFIG_SEND_BUFFER_SIZE);
    if (NULL == buffer)
    {
        log_error("function call `net_buffer_create` failed");
    _e1:
        return -1;
    }

    memcpy(buffer->data_ptr, http_resonse, strlen(http_resonse));

    buffer->data_size = strlen(http_resonse);

    net_client_add_send_buffer(client, buffer);

    if (-1 == net_client_send_data(client, worker))
    {
        log_error("function call `net_client_send_data` failed");

        goto _e1;
    }

    return -1;
}

int net_client_handle_data(struct net_client* client, struct net_worker* worker)
{
    while (1)
    {
        struct net_buffer* buffer = net_client_get_receive_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        while (buffer->data_size > 0)
        {
            char* ptr = strstr(buffer->data_ptr, "\r\n\r\n");
            if (NULL == ptr)
            {
                break;
            }

            if (-1 == net_client_send_hello_world_test(client, worker))
            {
                return -1;
            }

            int offset = ptr - buffer->data_ptr + 4;

            buffer->data_size -= offset;
            buffer->data_ptr += offset;
        }

        net_client_remove_receive_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    return 0;
}

int net_client_receive_data(struct net_client* client, struct net_worker* worker)
{
    while (1)
    {
        struct net_buffer* buffer = net_buffer_create(CONFIG_RECV_BUFFER_SIZE);
        if (NULL == buffer)
        {
            log_error("function call `net_buffer_create` failed");
        _e1:
            return -1;
        }

        int length = recv(client->client_socket, buffer->data_ptr, CONFIG_RECV_BUFFER_SIZE, 0);
        if (0 >= length)
        {
            net_buffer_destroy(buffer);

            if (-1 == length && EAGAIN == errno)
            {
                log_debug("need to recv again later");

                break;
            }

            if (0 != length)
            {
                log_error("system call `recv` failed with error %d", errno);
            }

            goto _e1;
        }

        buffer->data_size = length;

        net_client_add_receive_buffer(client, buffer);
    }

    if (-1 == net_client_handle_data(client, worker))
    {
        log_error("function call `net_client_handle_data` failed");

        goto _e1;
    }

    return 0;
}

void net_client_destroy(struct net_client* client)
{
    struct net_buffer* buffer = NULL;

    while (1)
    {
        buffer = net_client_get_send_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        net_client_remove_send_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    while (1)
    {
        buffer = net_client_get_receive_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        net_client_remove_receive_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    free(client);

    log_debug("client 0x%08X is destroyed", client);
}

struct net_client* net_worker_get_client(struct net_worker* worker)
{
    return container_of(linked_list_get_item(&worker->__client_list), struct net_client, __item);
}

void net_worker_remove_client(struct net_worker* worker, struct net_client* client)
{
    linked_list_remove_item(&worker->__client_list, &client->__item);
}

void net_worker_add_client(struct net_worker* worker, struct net_client* client)
{
    linked_list_add_item(&worker->__client_list, &client->__item);
}

void net_worker_close_client(struct net_worker* worker, struct net_client* client, int reason)
{
    log_debug("client 0x%08X with socket %d is being closed with status %d",
        client, client->client_socket, client->client_status);

    epoll_ctl(worker->epoll_handle, EPOLL_CTL_DEL, client->client_socket, NULL);

    close(client->client_socket);

    net_client_destroy(client);
}

int net_worker_handle_client_timeout(struct net_worker* worker)
{
    while (1)
    {
        struct net_client* client = net_worker_get_client(worker);
        if (NULL == client)
        {
            log_debug("no client in the list");

            break;
        }

        int timeout = net_client_get_remaining_time(client);
        if (timeout > 0)
        {
            return timeout;
        }

        net_worker_remove_client(worker, client);

        net_worker_close_client(worker, client, CLOSED_TIMEOUT);
    }

    return -1;
}

void net_worker_handle_client_event(struct net_worker* worker, struct epoll_event* event)
{
    do
    {
        struct net_client* client = (struct net_client*)event->data.ptr;

        net_worker_remove_client(worker, client);

        if (event->events & EPOLLERR)
        {
            log_error("error happened with client socket");
        _e1:
            net_worker_close_client(worker, client, CLOSED_ERROR);
            break;
        }

        if (event->events & EPOLLIN)
        {
            if (-1 == net_client_receive_data(client, worker))
            {
                log_error("function call `net_client_receive_data` failed");

                goto _e1;
            }
        }

        if (event->events & EPOLLOUT)
        {
            if (-1 == net_client_send_data(client, worker))
            {
                log_error("function call `net_client_send_data` failed");

                goto _e1;
            }
        }

        net_client_reset_expire_time(client);

        net_worker_add_client(worker, client);

    } while (0);
}

void net_worker_signal_handler(int signal, siginfo_t* sig_info, void* context)
{
    struct net_worker* worker = (struct net_worker*)sig_info->si_value.sival_ptr;
    if (SIGINT == signal)
    {
        worker->worker_status = NET_WORKER_STATUS_EXIT;

        log_debug("worker 0x%08X received SIGINT", worker);
    }
}

int signal_init(int* signums, int signal_size, void (*signal_handler)(int, siginfo_t*, void*))
{
    struct sigaction action = { { 0 } };
    if (-1 == sigfillset(&action.sa_mask))
    {
        log_error("system call `sigfillset` failed with error %d", errno);
    _e1:
        return -1;
    }
    
    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART;

    for (int i = 0; i < signal_size; i++)
    {
        if (-1 == sigaction(signums[i], &action, NULL))
        {
            log_error("system call `sigaction` failed with error %d", errno);

            goto _e1;
        }
    }

    return 0;
}

void* net_worker_thread_main(void* args)
{
    int signums[] = { SIGINT, SIGUSR1, SIGUSR2 };
    if (-1 == signal_init(signums, sizeof(signums) / sizeof(int), net_worker_signal_handler))
    {
        log_error("function call `signal_init` failed");

        return NULL;
    }

    struct net_worker* worker = (struct net_worker*)args;

    while (1)
    {
        if (NET_WORKER_STATUS_READY != worker->worker_status)
        {
            break;
        }

        struct epoll_event events[EPOLL_EVENT_SIZE] = { { 0 } };

        int event_count = epoll_wait(worker->epoll_handle, events, 
            EPOLL_EVENT_SIZE, net_worker_handle_client_timeout(worker));

        for (int i = 0; i < event_count; i ++)
        {
            net_worker_handle_client_event(worker, &events[i]);
        }
    }

    log_debug("worker 0x%08X is exited with status %d", worker, worker->worker_status);

    return NULL;
}

struct net_worker* net_worker_create()
{
    struct net_worker* worker = calloc(1, sizeof(struct net_worker));
    if (NULL == worker)
    {
        log_error("system call `calloc` failed with error %d", errno);
    _e1:
        return NULL;
    }

    worker->epoll_handle = epoll_create(EPOLL_EVENT_SIZE);
    if (-1 == worker->epoll_handle)
    {
        log_error("system call `epoll_create` failed with error %d", errno);
    _e2:
        free(worker);
        goto _e1;
    }

    worker->worker_status = NET_WORKER_STATUS_READY;

    int result = pthread_create(&worker->worker_thread, NULL, net_worker_thread_main, worker);
    if (0 != result)
    {
        log_error("system call `pthread_create` failed with error %d", result);

        close(worker->epoll_handle);
        goto _e2;
    }

    log_debug("worker 0x%08X is created", worker);

    return worker;
}

void net_worker_destroy(struct net_worker* worker)
{
    log_debug("--> enter %s", __FUNCTION__);
    
    union sigval sig_data = { .sival_ptr = worker };
    pthread_sigqueue(worker->worker_thread, SIGINT, sig_data);

    pthread_join(worker->worker_thread, NULL);

    while (1)
    {
        struct net_client* client = net_worker_get_client(worker);
        if (NULL == client)
        {
            break;
        }

        net_worker_remove_client(worker, client);

        net_worker_close_client(worker, client, CLOSED_EXIT);
    }

    close(worker->epoll_handle);

    free(worker);

    log_debug("worker 0x%08X is destroyed", worker);
}

int create_listen_socket_and_bind(const char* bind_addr, int listen_port)
{
    int listen_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (-1 == listen_socket)
    {
        log_error("system call `socket` failed with error %d", errno);
    _e1:
        return -1;
    }

    struct sockaddr_in addr_in = { 0 };
    addr_in.sin_addr.s_addr = inet_addr(bind_addr);
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(listen_port);

    if (-1 == bind(listen_socket, (struct sockaddr*)&addr_in, sizeof(struct sockaddr_in)))
    {
        log_error("system call `bind` failed with error %d", errno);
    _e2:
        close(listen_socket);
        goto _e1;
    }

    if (-1 == listen(listen_socket, CONFIG_LISTEN_BACKLOG))
    {
        log_error("system call `listen` failed with error %d", errno);
        goto _e2;
    }

    log_debug("socket %d is listen at %s:%d", listen_socket, bind_addr, listen_port);

    return listen_socket;
}

struct net_worker* net_server_get_worker(struct net_server* server)
{
    return container_of(linked_list_get_item(&server->__worker_list), struct net_worker, __item);
}

void net_server_add_worker(struct net_server* server, struct net_worker* worker)
{
    linked_list_add_item(&server->__worker_list, &worker->__item);
}

void net_server_remove_worker(struct net_server* server, struct net_worker* worker)
{
    linked_list_remove_item(&server->__worker_list, &worker->__item);
}

int net_server_register_client(struct net_server* server, struct net_client* client)
{
    struct net_worker* worker = net_server_get_worker(server);
    if (NULL == worker)
    {
        log_error("no worker in the list");
    _e1:
        return -1;
    }

    net_server_remove_worker(server, worker);

    struct epoll_event event = { 0 };
    event.data.ptr = client;
    event.events = EPOLLIN | EPOLLET;

    if (-1 == epoll_ctl(worker->epoll_handle, EPOLL_CTL_ADD, client->client_socket, &event))
    {
        log_error("system call `epoll_ctl` failed with error %d", errno);

        net_server_add_worker(server, worker);
        goto _e1;
    }

    client->registered_event = event.events;

    net_worker_add_client(worker, client);

    net_server_add_worker(server, worker);

    return 0;
}

int net_server_accept_new_client(struct net_server* server)
{
    while (1)
    {
        int client_socket = accept(server->listen_socket, NULL, NULL);
        if (-1 == client_socket)
        {
            break;
        }

        if (-1 == set_socket_to_nonblock(client_socket))
        {
            log_error("function call `set_socket_to_nonblock` failed");
        _e1:
            close(client_socket);
            continue;
        }

        struct net_client* client = net_client_create(client_socket, NET_CLIENT_TYPE_UNKNOWN);
        if (NULL == client)
        {
            log_error("function call `net_client_create` failed");
            
            goto _e1;
        }

        if (-1 == net_server_register_client(server, client))
        {
            net_client_destroy(client);
            goto _e1;
        }
        
        log_debug("new client 0x%08X with socket %d is connected", client, client_socket);
    }

    return (EAGAIN == errno) ? 0 : -1;
}

void net_server_signal_handler(int signal, siginfo_t* sig_info, void* context)
{
    struct net_server* server = (struct net_server*)sig_info->si_value.sival_ptr;
    if (SIGINT == signal)
    {
        server->server_status = NET_SERVER_STATUS_EXIT;

        log_debug("server 0x%08X received SIGINT", server);
    }
}

void* net_server_thread_main(void* args)
{
    int signums[] = { SIGINT, SIGUSR1, SIGUSR2 };
    if (-1 == signal_init(signums, sizeof(signums) / sizeof(int), net_server_signal_handler))
    {
        log_error("function call `signal_init` failed");

        return NULL;
    }

    struct net_server* server = (struct net_server*)args;

    while (1)
    {
        if (NET_SERVER_STATUS_READY != server->server_status)
        {
            break;
        }

        struct epoll_event events[EPOLL_EVENT_SIZE] = { { 0 } };

        int event_count = epoll_wait(server->epoll_handle, events, EPOLL_EVENT_SIZE, -1);

        for (int i = 0; i < event_count; i ++)
        {
            if (events[i].data.fd == server->listen_socket)
            {
                net_server_accept_new_client(server);
            }
        }
    }

    log_debug("server 0x%08X is exited with status %d", server, server->server_status);

    return NULL;
}

struct net_server* net_server_create(const char* bind_addr, int listen_port, int worker_size)
{
    struct net_server* server = calloc(1, sizeof(struct net_server));
    if (NULL == server)
    {
        log_error("system call `calloc` failed with error %d", errno);
    _e1:
        return NULL;
    }

    int listen_socket = create_listen_socket_and_bind(bind_addr, listen_port);
    if (-1 == listen_socket)
    {
        log_error("function call `create_listen_socket_and_bind` failed");
    _e2:
        free(server);
        goto _e1;
    }

    server->epoll_handle = epoll_create(EPOLL_EVENT_SIZE);
    if (-1 == server->epoll_handle)
    {
        log_error("system call `epoll_create` failed with error %d", errno);
    _e3:
        close(listen_socket);
        goto _e2;
    }

    struct epoll_event event = { 0 };
    event.data.fd = listen_socket;
    event.events = EPOLLET | EPOLLIN;

    if (-1 == epoll_ctl(server->epoll_handle, EPOLL_CTL_ADD, listen_socket, &event))
    {
        log_error("system call `epoll_Ctl` failed with error %d", errno);

        close(server->epoll_handle);
        goto _e3;
    }

    log_debug("server 0x%08X is created with socket %d", server, listen_socket);

    return server;
}

void net_server_destroy_workers(struct net_server* server)
{
    while (1)
    {
        struct net_worker* worker = net_server_get_worker(server);
        if (NULL == worker)
        {
            break;
        }

        net_server_remove_worker(server, worker);

        net_worker_destroy(worker);
    }
}

int net_server_create_workers(struct net_server* server, int worker_size)
{
    for (int i = 0; i < worker_size; i++)
    {
        struct net_worker* worker = net_worker_create();
        if (NULL == worker)
        {
            continue;
        }

        net_server_add_worker(server, worker);
    }

    return 0;
}

void net_server_destroy(struct net_server* server)
{
    union sigval sig_data = { .sival_ptr = server };
    pthread_sigqueue(server->server_thread, SIGINT, sig_data);

    pthread_join(server->server_thread, NULL);

    net_server_destroy_workers(server);

    epoll_ctl(server->epoll_handle, EPOLL_CTL_DEL, server->listen_socket, NULL);

    close(server->epoll_handle);

    free(server);

    log_debug("server 0x%08X is destroyed", server);
}

int net_server_run_event_loop(struct net_server* server, int worker_size)
{
    if (-1 == net_server_create_workers(server, worker_size))
    {
        log_error("function call `net_server_create_workers` failed");
    _e1:
        return -1;
    }

    server->server_status = NET_SERVER_STATUS_READY;

    int result = pthread_create(&server->server_thread, NULL, net_server_thread_main, server);
    if (0 != result)
    {
        log_error("system call `pthread_create` failed with error %d", result);

        net_server_destroy_workers(server);
        goto _e1;
    }

    return 0;
}

int main(int argc, char const *argv[])
{
    struct net_server* server = net_server_create("0.0.0.0", 9999, 2);
    if (NULL == server)
    {
    _e1:
        return -1;
    }

    sigset_t sigset = { { 0 } };

    if (-1 == sigfillset(&sigset))
    {
    _e2:
        net_server_destroy(server);
        goto _e1;
    }

    if (-1 == net_server_run_event_loop(server, 1))
    {
        goto _e2;
    }

    while (1)
    {
        int signum = 0;
        if (0 != sigwait(&sigset, &signum))
        {
            continue;
        }

        if (SIGINT == signum)
        {
            log_debug("main thread received SIGINT");

            break;
        }
    }

    net_server_destroy(server);

    return 0;
}