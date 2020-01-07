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

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CONFIG_CLIENT_DEFAULT_TIMEOUT       (1800 * 1000)
#define CONFIG_LISTEN_BACKLOG               256
#define CONFIG_LOG_LEVEL                    LOG_LEVEL_DEBUG
#define CONFIG_RECV_BUFFER_SIZE             (4096 - sizeof(struct net_buffer))
#define CONFIG_SEND_BUFFER_SIZE             (4096 - sizeof(struct net_buffer))
#define CONFIG_BIND_ADDRESS                 "0.0.0.0"
#define CONFIG_LISTEN_PORT                  9999
#define CONFIG_SSL_ENABLE                   1
#define CONFIG_SERVER_SIZE                  1
#define CONFIG_WORKER_SIZE                  2
#define CONFIG_CRT_FILE                     "server.crt"
#define CONFIG_KEY_FILE                     "server.key"
#define CONFIG_CIPHER_SUIT                  "ECDHE-ECDSA-AES256-GCM-SHA384:"    \
                                            "ECDHE-RSA-AES256-GCM-SHA384:"      \
                                            "ECDHE-ECDSA-CHACHA20-POLY1305:"    \
                                            "ECDHE-RSA-CHACHA20-POLY1305:"      \
                                            "ECDHE-ECDSA-AES128-GCM-SHA256:"    \
                                            "ECDHE-RSA-AES128-GCM-SHA256:"      \
                                            "ECDHE-ECDSA-AES256-SHA384:"        \
                                            "ECDHE-RSA-AES256-SHA384:"          \
                                            "ECDHE-ECDSA-AES128-SHA256:"        \
                                            "ECDHE-RSA-AES128-SHA256"

#define EPOLL_EVENT_SIZE                    256

#define LOG_BUFFER_SIZE                     4096

#define NET_WORKER_STATUS_READY             0
#define NET_WORKER_STATUS_EXIT              1

#define NET_SERVER_STATUS_READY             0
#define NET_SERVER_STATUS_EXIT              1

#define NET_CLIENT_STATUS_CONNECTED         0
#define NET_CLIENT_STATUS_SSL_WAIT          1

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
#define LOG_LEVEL_NONE                      4

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

#define log_function_entry()                \
    log_debug("----> %s", __FUNCTION__)

#define log_function_leave()                \
    log_debug("<---- %s", __FUNCTION__)

struct list_item
{
    struct list_item* next;
    struct list_item* prev;
};

struct linked_list
{
    int list_size;
    int thread_safe;
    pthread_spinlock_t lock;
    struct list_item* head;
    struct list_item* tail;
};

struct net_buffer
{
    char* data_ptr;
    int data_size;
    int buffer_size;
    struct list_item __item;
};

struct net_client
{
    int client_socket;
    int expire_time;
    int registered_events;
    int client_status;
    int client_type;
    SSL* ssl_channel;
    struct list_item __item;
    struct linked_list __data;
    struct linked_list __send;
    struct linked_list __recv;
};

struct net_worker
{
    int worker_status;
    int epoll_handle;
    SSL_CTX* ssl_ctx;
    pthread_t worker_thread;
    struct list_item __item;
    struct linked_list __client;
};

struct net_server
{
    int listen_socket;
    int epoll_handle;
    int server_status;
    int ssl_enable;
    pthread_t server_thread;
    struct list_item __item;
    struct linked_list __worker;
};

struct net_faker
{
    struct linked_list __server;
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

    int length = sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d.%04ld [%s] file=%s "
        "line=%d thread=%p ", local_tm.tm_year + 1900, local_tm.tm_mon + 1,
        local_tm.tm_mday, local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec,
        tv.tv_usec / 1000, prefix[level % 4], file, line, (void*)pthread_self());

    va_list ap; va_start(ap, format); vsprintf(buffer + length, format, ap); va_end(ap);

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

void signal_handler(int signal, siginfo_t* sig_info, void* context)
{
    if (SIGUSR1 == signal)
    {
        struct net_server* server = (struct net_server*)sig_info->si_value.sival_ptr;

        server->server_status = NET_SERVER_STATUS_EXIT;

        log_debug("server %p received SIGUSR1", server);
    }

    if (SIGUSR2 == signal)
    {
        struct net_worker* worker = (struct net_worker*)sig_info->si_value.sival_ptr;

        worker->worker_status = NET_WORKER_STATUS_EXIT;

        log_debug("worker %p received SIGUSR2", worker);
    }
}

int signal_init(int* signums, int signal_size)
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

int linked_list_initialize(struct linked_list* list)
{
    if (0 != pthread_spin_init(&list->lock, PTHREAD_PROCESS_PRIVATE))
    {
        return -1;
    }

    list->thread_safe = 1;

    return 0;
}

int linked_list_uninitialize(struct linked_list* list)
{
    if (0 != pthread_spin_destroy(&list->lock))
    {
        return -1;
    }

    list->thread_safe = 0;

    return 0;
}

void linked_list_lock(struct linked_list* list)
{
    if (1 == list->thread_safe)
    {
        pthread_spin_lock(&list->lock);
    }
}

void linked_list_unlock(struct linked_list* list)
{
    if (1 == list->thread_safe)
    {
        pthread_spin_unlock(&list->lock);
    }
}

struct list_item* linked_list_get_top_item(struct linked_list* list)
{
    linked_list_lock(list);

    struct list_item* item = list->head;

    linked_list_unlock(list);

    return item;
}

struct list_item* linked_list_get_back_item(struct linked_list* list)
{
    linked_list_lock(list);

    struct list_item* item = list->tail;

    linked_list_unlock(list);

    return item;
}

int linked_list_get_size(struct linked_list* list)
{
    linked_list_lock(list);

    int size = list->list_size;

    linked_list_unlock(list);

    return size;
}

void linked_list_push_item(struct linked_list* list, struct list_item* item)
{
    linked_list_lock(list);

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

    list->list_size ++;

    linked_list_unlock(list);
}

void linked_list_remove_item(struct linked_list* list, struct list_item* item)
{
    linked_list_lock(list);

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

    list->list_size --;

    linked_list_unlock(list);
}

SSL_CTX* ssl_ctx_create()
{
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_method());
    if (NULL == ssl_ctx)
    {
        log_error("system call `SSL_CTX_new` failed with error %d", ERR_get_error());
    _e1:
        return NULL;
    }

    if (1 != SSL_CTX_use_certificate_file(ssl_ctx, CONFIG_CRT_FILE, SSL_FILETYPE_PEM))
    {
        log_error("system call `SSL_CTX_use_certificate_file` failed with error %d",
            ERR_get_error());
    _e2:
        SSL_CTX_free(ssl_ctx);

        goto _e1;
    }

    if (1 != SSL_CTX_use_PrivateKey_file(ssl_ctx, CONFIG_KEY_FILE, SSL_FILETYPE_PEM))
    {
        log_error("system call `SSL_CTX_use_PrivateKey_file` failed with error %d",
            ERR_get_error());

        goto _e2;
    }

    if (1 != SSL_CTX_check_private_key(ssl_ctx))
    {
        log_error("system call `SSL_CTX_check_private_key` failed with error %d",
            ERR_get_error());

        goto _e2;
    }

    if (1 != SSL_CTX_set_cipher_list(ssl_ctx, CONFIG_CIPHER_SUIT))
    {
        log_error("system call `SSL_CTX_set_cipher_list` failed with error %d",
            ERR_get_error());

        goto _e2;
    }

    return ssl_ctx;
}

void ssl_ctx_destroy(SSL_CTX* ssl_ctx)
{
    SSL_CTX_free(ssl_ctx);
}

SSL* ssl_channel_create(SSL_CTX* ssl_ctx)
{
    SSL* ssl_channel = SSL_new(ssl_ctx);
    if (NULL == ssl_channel)
    {
        log_error("system call `SSL_new` failed with error %d", ERR_get_error());
    _e1:
        return NULL;
    }

    BIO* rbio = BIO_new(BIO_s_mem());
    if (NULL == rbio)
    {
        log_error("system call `BIO_new` failed with error %d", ERR_get_error());
    _e2:
        SSL_free(ssl_channel);

        goto _e1;
    }

    BIO* wbio = BIO_new(BIO_s_mem());
    if (NULL == wbio)
    {
        log_error("system call `BIO_new` failed with error %d", ERR_get_error());

        BIO_free(rbio);

        goto _e2;
    }

    SSL_set_bio(ssl_channel, rbio, wbio);

    return ssl_channel;
}

void ssl_channel_destroy(SSL* ssl_channel)
{
    SSL_free(ssl_channel);
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
    buffer->data_size = 0;

    buffer->buffer_size = buffer_size;

    log_debug("buffer %p with size %d is created", buffer, buffer_size);

    return buffer;
}

void net_buffer_destroy(struct net_buffer* buffer)
{
    free(buffer);

    log_debug("buffer %p is destroyed", buffer);
}

int net_buffer_get_available_size(struct net_buffer* buffer)
{
    return buffer->buffer_size - (buffer->data_ptr - (char*)(buffer + 1)) - buffer->data_size;
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

    log_debug("client %p with socket %d is created", client, client_socket);

    return client;
}

struct net_buffer* net_client_get_top_send_buffer(struct net_client* client)
{
    struct list_item* item = linked_list_get_top_item(&client->__send);
    return container_of(item, struct net_buffer, __item);
}

struct net_buffer* net_client_get_back_send_buffer(struct net_client* client)
{
    struct list_item* item = linked_list_get_back_item(&client->__send);
    return container_of(item, struct net_buffer, __item);
}

void net_client_remove_send_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_remove_item(&client->__send, &buffer->__item);
}

void net_client_push_send_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_push_item(&client->__send, &buffer->__item);
}

struct net_buffer* net_client_get_top_data_buffer(struct net_client* client)
{
    struct list_item* item = linked_list_get_top_item(&client->__data);
    return container_of(item, struct net_buffer, __item);
}

struct net_buffer* net_client_get_back_data_buffer(struct net_client* client)
{
    struct list_item* item = linked_list_get_back_item(&client->__data);
    return container_of(item, struct net_buffer, __item);
}

void net_client_remove_data_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_remove_item(&client->__data, &buffer->__item);
}

void net_client_push_data_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_push_item(&client->__data, &buffer->__item);
}

struct net_buffer* net_client_get_top_recv_buffer(struct net_client* client)
{
    struct list_item* item = linked_list_get_top_item(&client->__recv);
    return container_of(item, struct net_buffer, __item);
}

struct net_buffer* net_client_get_back_recv_buffer(struct net_client* client)
{
    struct list_item* item = linked_list_get_back_item(&client->__recv);
    return container_of(item, struct net_buffer, __item);
}

void net_client_remove_recv_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_remove_item(&client->__recv, &buffer->__item);
}

void net_client_push_recv_buffer(struct net_client* client, struct net_buffer* buffer)
{
    linked_list_push_item(&client->__recv, &buffer->__item);
}

int net_client_send_data(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    struct epoll_event event = { 0 };
    event.data.ptr = client;
    event.events = EPOLLIN | EPOLLET;

    while (1)
    {
        struct net_buffer* buffer = net_client_get_top_send_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        while (buffer->data_size > 0)
        {
            int length = send(client->client_socket, buffer->data_ptr, buffer->data_size, 0);
            if (0 >= length)
            {
                if (-1 == length && EAGAIN == errno)
                {
                    event.events |= EPOLLOUT;

                    goto _end;
                }

                if (0 != length)
                {
                    log_error("system call `send` failed with error %d", errno);
                }

            _e1:
                log_function_leave();

                return -1;
            }

            log_debug("%d bytes data are sent to client %d with socket %d",
                length, client, client->client_socket);

            buffer->data_ptr += length;
            buffer->data_size -= length;
        }

        net_client_remove_send_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

_end:
    if (event.events != client->registered_events)
    {
        if (-1 == epoll_ctl(worker->epoll_handle, EPOLL_CTL_MOD, client->client_socket, &event))
        {
            log_error("system call `epoll_ctl` failed with error %d", errno);

            goto _e1;
        }

        client->registered_events = event.events;
    }

    log_function_leave();

    return 0;
}

int net_client_read_data_from_ssl(struct net_client* client)
{
    log_function_entry();

    while (1)
    {
        int is_new_buffer = 0, available_size = CONFIG_SEND_BUFFER_SIZE;

        struct net_buffer* buffer = net_client_get_back_send_buffer(client);
        if (NULL == buffer || 0 >= (available_size = net_buffer_get_available_size(buffer)))
        {
            buffer = net_buffer_create(CONFIG_SEND_BUFFER_SIZE);
            if (NULL == buffer)
            {
                log_error("function call `net_buffer_create` failed");
            _e1:
                log_function_leave();

                return -1;
            }

            is_new_buffer = 1;
        }

        int length = BIO_read(SSL_get_wbio(client->ssl_channel),
            buffer->data_ptr + buffer->data_size, available_size);
        if (0 >= length)
        {
            if (1 == is_new_buffer)
            {
                net_buffer_destroy(buffer);
            }

            if (0 == BIO_should_retry(SSL_get_wbio(client->ssl_channel)))
            {
                log_error("system call `BIO_read` failed with error %d", ERR_get_error());

                goto _e1;
            }

            break;
        }

        buffer->data_size += length;

        log_debug("%d bytes encrypted data are read from ssl channel", length);

        if (1 == is_new_buffer)
        {
            net_client_push_send_buffer(client, buffer);
        }
    }

    log_function_leave();

    return 0;
}

int net_client_send_user_data(struct net_client* client,
    char* data, int size, struct net_worker* worker)
{
    log_function_entry();

    int data_size = size;

    while (data_size > 0)
    {
        int is_new_buffer = 0, available_size = CONFIG_SEND_BUFFER_SIZE;

        struct net_buffer* buffer = net_client_get_back_send_buffer(client);
        if (NULL == buffer || 0 >= (available_size = net_buffer_get_available_size(buffer)))
        {
            buffer = net_buffer_create(CONFIG_SEND_BUFFER_SIZE);
            if (NULL == buffer)
            {
                log_error("function call `net_buffer_create` failed");
            _e1:
                log_function_leave();

                return -1;
            }

            is_new_buffer = 1;
        }

        int copy_size = data_size > available_size ? available_size : data_size;

        memcpy(buffer->data_ptr + buffer->data_size, data, copy_size);

        buffer->data_size += copy_size;

        if (1 == is_new_buffer)
        {
            net_client_push_send_buffer(client, buffer);
        }

        data += copy_size;
        data_size -= copy_size;
    }

    if (-1 == net_client_send_data(client, worker))
    {
        log_error("function call `net_client_send_data` failed");

        goto _e1;
    }

    log_function_leave();

    return size - data_size;
}

int net_client_send_user_data_ssl(struct net_client* client,
    char* data, int size, struct net_worker* worker)
{
    log_function_entry();

    int data_size = size;

    while (data_size > 0)
    {
        int length = SSL_write(client->ssl_channel, data, data_size);
        if (0 >= length)
        {
            int ssl_ret = SSL_get_error(client->ssl_channel, length);
            if (SSL_ERROR_WANT_READ == ssl_ret || SSL_ERROR_WANT_WRITE == ssl_ret)
            {
                break;
            }

            log_error("system call `SSL_write` failed with error %d", ssl_ret);
        _e1:
            log_function_leave();

            return -1;
        }

        if (-1 == net_client_read_data_from_ssl(client))
        {
            log_error("function call `net_client_read_data_from_ssl` failed");

            goto _e1;
        }

        data += length;
        data_size -= length;
    }

    if (-1 == net_client_send_data(client, worker))
    {
        log_error("function call `net_client_send_data` failed");

        goto _e1;
    }

    log_function_leave();

    return size - data_size;
}

int net_client_finish_ssl_connection(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    int ssl_ret = SSL_accept(client->ssl_channel);
    if (0 >= ssl_ret)
    {
        ssl_ret = SSL_get_error(client->ssl_channel, ssl_ret);
        if ((SSL_ERROR_WANT_READ != ssl_ret) && (SSL_ERROR_WANT_WRITE != ssl_ret))
        {
            log_error("system call `SSL_accept` failed with error %d", ssl_ret);
        _e1:
            log_function_leave();

            return -1;
        }
    }

    if (-1 == net_client_read_data_from_ssl(client))
    {
        log_error("function call `net_client_read_data_from_ssl` failed");

        goto _e1;
    }

    if (-1 == net_client_send_data(client, worker))
    {
        log_error("function call `net_client_send_data` failed");

        goto _e1;
    }

    if (1 == SSL_is_init_finished(client->ssl_channel))
    {
        client->client_status = NET_CLIENT_STATUS_CONNECTED;

        log_debug("client %p with socket %d finished ssl connection",
            client, client->client_socket);
    }

    log_function_leave();

    return 0;
}

int net_client_write_data_to_ssl(struct net_client* client)
{
    log_function_entry();

    while (1)
    {
        struct net_buffer* buffer = net_client_get_top_recv_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        while (buffer->data_size > 0)
        {
            int length = BIO_write(SSL_get_rbio(client->ssl_channel),
                buffer->data_ptr, buffer->data_size);

            if (0 >= length)
            {
                if (0 == BIO_should_retry(SSL_get_rbio(client->ssl_channel)))
                {
                    log_error("system call `BIO_write` failed with error %d", ERR_get_error());

                    log_function_leave();

                    return -1;
                }

                goto _end;
            }

            log_debug("%d bytes data are written to ssl channel", length);

            buffer->data_ptr += length;
            buffer->data_size -= length;
        }

        net_client_remove_recv_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

_end:
    log_function_leave();

    return 0;
}

int net_client_send_hello_world(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    char* http_response = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/html; charset=utf-8\r\n"
                          "Content-Length: 11\r\n"
                          "Server: Faker/1.1\r\n\r\n"
                          "Hello World";

    if (NULL != client->ssl_channel)
    {
        if (-1 == net_client_send_user_data_ssl(client,
            http_response, strlen(http_response), worker))
        {
            log_error("function call `net_client_send_user_data_ssl` failed");
        _e1:
            log_function_leave();

            return -1;
        }
    }
    else
    {
        if (-1 == net_client_send_user_data(client,
            http_response, strlen(http_response), worker))
        {
            log_error("function call `net_client_send_user_data` failed");

            goto _e1;
        }
    }

    log_function_leave();

    return 0;
}

int net_client_handle_user_data(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    while (1)
    {
        struct net_buffer* buffer = net_client_get_top_data_buffer(client);
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

            if (-1 == net_client_send_hello_world(client, worker))
            {
                log_error("function call `net_client_send_hello_world` failed");

                return -1;
            }

            int offset = ptr - buffer->data_ptr + 4;

            buffer->data_ptr += offset;
            buffer->data_size -= offset;
        }

        net_client_remove_data_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    log_function_leave();

    return 0;
}

int net_client_handle_ssl_data(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    while (1)
    {
        int is_new_buffer = 0, available_size = CONFIG_RECV_BUFFER_SIZE;

        struct net_buffer* buffer = net_client_get_back_data_buffer(client);
        if (NULL == buffer || 0 >= (available_size = net_buffer_get_available_size(buffer)))
        {
            buffer = net_buffer_create(CONFIG_RECV_BUFFER_SIZE);
            if (NULL == buffer)
            {
                log_error("function call `net_buffer_create` failed");
            _e1:
                log_function_leave();

                return -1;
            }

            is_new_buffer = 1;
        }

        int length = SSL_read(client->ssl_channel,
            buffer->data_ptr + buffer->data_size, available_size);
        if (0 >= length)
        {
            if (1 == is_new_buffer)
            {
                net_buffer_destroy(buffer);
            }

            int ssl_ret = SSL_get_error(client->ssl_channel, length);
            if (SSL_ERROR_WANT_READ == ssl_ret || SSL_ERROR_WANT_WRITE == ssl_ret)
            {
                break;
            }

            log_error("system call `SSL_read` failed with error %d", ssl_ret);

            goto _e1;
        }

        buffer->data_size += length;

        log_debug("%d bytes user data are read from ssl channel", length);

        if (1 == is_new_buffer)
        {
            net_client_push_data_buffer(client, buffer);
        }
    }

    if (-1 == net_client_handle_user_data(client, worker))
    {
        log_error("function call `net_client_handle_user_data` failed");

        goto _e1;
    }

    log_function_leave();

    return 0;
}

int net_client_handle_received_data(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    if (NULL != client->ssl_channel)
    {
        if (-1 == net_client_write_data_to_ssl(client))
        {
            log_error("function call `net_client_write_data_to_ssl` failed");
        _e1:
            log_function_leave();

            return -1;
        }

        if (NET_CLIENT_STATUS_SSL_WAIT == client->client_status)
        {
            if (-1 == net_client_finish_ssl_connection(client, worker))
            {
                log_error("function call `net_client_finish_ssl_connection` failed");

                goto _e1;
            }
        }

        if (NET_CLIENT_STATUS_CONNECTED == client->client_status)
        {
            if (-1 == net_client_handle_ssl_data(client, worker))
            {
                log_error("function call `net_client_handle_ssl_data` failed");

                goto _e1;
            }
        }
    }
    else
    {
        if (-1 == net_client_handle_user_data(client, worker))
        {
            log_error("function call `net_client_handle_user_data` failed");

            goto _e1;
        }
    }

    log_function_leave();

    return 0;
}

int net_client_receive_data(struct net_client* client, struct net_worker* worker)
{
    log_function_entry();

    while (1)
    {
        int is_new_buffer = 0, available_size = CONFIG_RECV_BUFFER_SIZE;

        struct net_buffer* buffer = NULL;
        if (NULL != client->ssl_channel)
        {
            buffer = net_client_get_back_recv_buffer(client);
        }
        else
        {
            buffer = net_client_get_back_data_buffer(client);
        }

        if (NULL == buffer || 0 >= (available_size = net_buffer_get_available_size(buffer)))
        {
            buffer = net_buffer_create(CONFIG_RECV_BUFFER_SIZE);
            if (NULL == buffer)
            {
                log_error("function call `net_buffer_create` failed");
            _e1:
                log_function_leave();

                return -1;
            }

            is_new_buffer = 1;
        }

        int length = recv(client->client_socket, 
            buffer->data_ptr + buffer->data_size, available_size, 0);
        if (0 >= length)
        {
            if (1 == is_new_buffer)
            {
                net_buffer_destroy(buffer);
            }

            if (-1 == length && EAGAIN == errno)
            {
                break;
            }

            if (0 != length)
            {
                log_error("system call `recv` failed with error %d", errno);
            }

            goto _e1;
        }

        buffer->data_size += length;

        log_debug("%d bytes data are received from client %p with socket %d",
            length, client, client->client_socket);

        if (1 == is_new_buffer)
        {
            if (NULL != client->ssl_channel)
            {
                net_client_push_recv_buffer(client, buffer);
            }
            else
            {
                net_client_push_data_buffer(client, buffer);
            }
        }
    }

    if (-1 == net_client_handle_received_data(client, worker))
    {
        log_error("function call `net_client_handle_received_data` failed");

        goto _e1;
    }

    log_function_leave();

    return 0;
}

void net_client_destroy(struct net_client* client)
{
    struct net_buffer* buffer = NULL;

    while (1)
    {
        buffer = net_client_get_top_send_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        net_client_remove_send_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    while (1)
    {
        buffer = net_client_get_top_recv_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        net_client_remove_recv_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    while (1)
    {
        buffer = net_client_get_top_data_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        net_client_remove_data_buffer(client, buffer);

        net_buffer_destroy(buffer);
    }

    if (NULL != client->ssl_channel)
    {
        ssl_channel_destroy(client->ssl_channel);
    }

    log_debug("client %p with socket %d is destroyed", client, client->client_socket);

    close(client->client_socket);

    free(client);
}

struct net_client* net_worker_get_top_client(struct net_worker* worker)
{
    struct list_item* item = linked_list_get_top_item(&worker->__client);
    return container_of(item, struct net_client, __item);
}

void net_worker_remove_client(struct net_worker* worker, struct net_client* client)
{
    linked_list_remove_item(&worker->__client, &client->__item);
}

void net_worker_push_client(struct net_worker* worker, struct net_client* client)
{
    linked_list_push_item(&worker->__client, &client->__item);
}

int net_worker_get_client_size(struct net_worker* worker)
{
    return linked_list_get_size(&worker->__client);
}

void net_worker_close_client(struct net_worker* worker, struct net_client* client, int reason)
{
    log_debug("client %p with socket %d is being closed with status %d for reason %d",
        client, client->client_socket, client->client_status, reason);

    epoll_ctl(worker->epoll_handle, EPOLL_CTL_DEL, client->client_socket, NULL);

    net_client_destroy(client);
}

int net_worker_handle_client_timeout(struct net_worker* worker)
{
    while (1)
    {
        struct net_client* client = net_worker_get_top_client(worker);
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

        if (NET_CLIENT_TYPE_CHANNEL_1 == client->client_type ||
            NET_CLIENT_TYPE_CHANNEL_2 == client->client_type)
        {
            net_client_reset_expire_time(client);

            net_worker_push_client(worker, client);
        }
        else
        {
            net_worker_close_client(worker, client, CLOSED_TIMEOUT);
        }
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

        net_worker_push_client(worker, client);

    } while (0);
}

void* net_worker_thread_main(void* args)
{
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

    log_debug("worker %p exited with status %d", worker, worker->worker_status);

    return NULL;
}

struct net_worker* net_worker_create(int ssl_enable)
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

    if (1 == ssl_enable && NULL == (worker->ssl_ctx = ssl_ctx_create()))
    {
        log_error("function call `ssl_ctx_create` failed");
    _e3:
        close(worker->epoll_handle);

        goto _e2;
    }

    if (-1 == linked_list_initialize(&worker->__client))
    {
        log_error("function call `linked_list_initialize` failed");

        ssl_ctx_destroy(worker->ssl_ctx);

        goto _e3;
    }

    worker->worker_status = NET_WORKER_STATUS_READY;

    log_debug("worker %p is created", worker);

    return worker;
}

int net_worker_run(struct net_worker* worker)
{
    int result = pthread_create(&worker->worker_thread, NULL, net_worker_thread_main, worker);
    if (0 != result)
    {
        log_error("system call `pthread_create` failed with error %d", result);

        return -1;
    }

    return 0;
}

void net_worker_destroy(struct net_worker* worker)
{
    if (0 != worker->worker_thread)
    {
        union sigval sig_data = { .sival_ptr = worker };
        pthread_sigqueue(worker->worker_thread, SIGUSR2, sig_data);

        pthread_join(worker->worker_thread, NULL);
    }

    linked_list_uninitialize(&worker->__client);

    while (1)
    {
        struct net_client* client = net_worker_get_top_client(worker);
        if (NULL == client)
        {
            break;
        }

        net_worker_remove_client(worker, client);

        net_worker_close_client(worker, client, CLOSED_EXIT);
    }

    ssl_ctx_destroy(worker->ssl_ctx);

    close(worker->epoll_handle);

    free(worker);

    log_debug("worker %p is destroyed", worker);
}

struct net_worker* net_server_get_top_worker(struct net_server* server)
{
    struct list_item* item = linked_list_get_top_item(&server->__worker);
    return container_of(item, struct net_worker, __item);
}

void net_server_push_worker(struct net_server* server, struct net_worker* worker)
{
    linked_list_push_item(&server->__worker, &worker->__item);
}

int net_server_get_worker_size(struct net_server* server)
{
    return linked_list_get_size(&server->__worker);
}

void net_server_remove_worker(struct net_server* server, struct net_worker* worker)
{
    linked_list_remove_item(&server->__worker, &worker->__item);
}

struct net_worker* net_server_find_balanced_worker(struct net_server* server)
{
    struct net_worker* worker = NULL, *temp = NULL;

    for (struct list_item* item = server->__worker.head; NULL != item; item = item->next)
    {
        temp = container_of(item, struct net_worker, __item);

        if (NULL == worker)
        {
            worker = temp;

            continue;
        }

        if (net_worker_get_client_size(temp) < net_worker_get_client_size(worker))
        {
            worker = temp;

            continue;
        }
    }

    return worker;
}

int net_server_register_client(struct net_server* server, struct net_client* client)
{
    struct net_worker* worker = net_server_find_balanced_worker(server);
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

    client->registered_events = event.events;

    if (1 == server->ssl_enable)
    {
        client->ssl_channel = ssl_channel_create(worker->ssl_ctx);
        if (NULL == client->ssl_channel)
        {
            log_error("function call `ssl_channel_create` failed");
        _e2:
            net_server_push_worker(server, worker);

            goto _e1;
        }
    }

    net_worker_push_client(worker, client);

    if (-1 == epoll_ctl(worker->epoll_handle, EPOLL_CTL_ADD, client->client_socket, &event))
    {
        log_error("system call `epoll_ctl` failed with error %d", errno);

        net_worker_remove_client(worker, client);

        goto _e2;
    }

    net_server_push_worker(server, worker);

    return 0;
}

int net_server_accept_new_client(struct net_server* server)
{
    while (1)
    {
        int client_socket = accept(server->listen_socket, NULL, NULL);
        if (-1 == client_socket)
        {
            if (-1 == client_socket && EAGAIN == errno)
            {
                break;
            }

            log_error("system call `accept` failed with error %d", errno);

            return -1;
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

        if (1 == server->ssl_enable)
        {
            client->client_status = NET_CLIENT_STATUS_SSL_WAIT;
        }

        if (-1 == net_server_register_client(server, client))
        {
            log_error("function call `net_server_register_client` failed");

            net_client_destroy(client);

            goto _e1;
        }

        log_debug("new client %p with socket %d is connected", client, client_socket);
    }

    return 0;
}

void* net_server_thread_main(void* args)
{
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

    log_debug("server %p exited with status %d", server, server->server_status);

    return NULL;
}

int net_server_bind_address(struct net_server* server, const char* bind_addr, int listen_port)
{
    server->listen_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (-1 == server->listen_socket)
    {
        log_error("system call `socket` failed with error %d", errno);
    _e1:
        return -1;
    }

    struct sockaddr_in addr_in = { 0 };
    addr_in.sin_addr.s_addr = inet_addr(bind_addr);
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(listen_port);

    if (-1 == bind(server->listen_socket, (struct sockaddr*)&addr_in, sizeof(struct sockaddr_in)))
    {
        log_error("system call `bind` failed with error %d", errno);
    _e2:
        close(server->listen_socket);

        goto _e1;
    }

    if (-1 == listen(server->listen_socket, CONFIG_LISTEN_BACKLOG))
    {
        log_error("system call `listen` failed with error %d", errno);

        goto _e2;
    }

    log_debug("socket %d is listen at %s:%d", server->listen_socket, bind_addr, listen_port);

    return 0;
}

struct net_server* net_server_create(const char* bind_addr, int listen_port, int ssl_enable)
{
    struct net_server* server = calloc(1, sizeof(struct net_server));
    if (NULL == server)
    {
        log_error("system call `calloc` failed with error %d", errno);
    _e1:
        return NULL;
    }

    if (-1 == net_server_bind_address(server, bind_addr, listen_port))
    {
        log_error("function call `net_server_bind_address` failed");
    _e2:
        free(server);

        goto _e1;
    }

    server->epoll_handle = epoll_create(EPOLL_EVENT_SIZE);
    if (-1 == server->epoll_handle)
    {
        log_error("system call `epoll_create` failed with error %d", errno);
    _e3:
        close(server->listen_socket);

        goto _e2;
    }

    struct epoll_event event = { 0 };
    event.data.fd = server->listen_socket;
    event.events = EPOLLET | EPOLLIN;

    if (-1 == epoll_ctl(server->epoll_handle, EPOLL_CTL_ADD, server->listen_socket, &event))
    {
        log_error("system call `epoll_Ctl` failed with error %d", errno);

        close(server->epoll_handle);

        goto _e3;
    }

    for (int i = 0; i < CONFIG_WORKER_SIZE; i++)
    {
        struct net_worker* worker = net_worker_create(ssl_enable);
        if (NULL == worker)
        {
            log_error("function call `net_worker_create` failed");

            continue;
        }

        net_server_push_worker(server, worker);
    }

    server->server_status = NET_SERVER_STATUS_READY;
    server->ssl_enable = ssl_enable;

    log_debug("server %p is created with socket %d", server, server->listen_socket);

    return server;
}

void net_server_destroy(struct net_server* server)
{
    if (0 != server->server_thread)
    {
        union sigval sig_data = { .sival_ptr = server };
        pthread_sigqueue(server->server_thread, SIGUSR1, sig_data);

        pthread_join(server->server_thread, NULL);
    }

    while (1)
    {
        struct net_worker* worker = net_server_get_top_worker(server);
        if (NULL == worker)
        {
            break;
        }

        net_server_remove_worker(server, worker);

        net_worker_destroy(worker);
    }

    epoll_ctl(server->epoll_handle, EPOLL_CTL_DEL, server->listen_socket, NULL);

    close(server->epoll_handle);

    close(server->listen_socket);

    free(server);

    log_debug("server %p is destroyed", server);
}

int net_server_run(struct net_server* server)
{
    if (0 == net_server_get_worker_size(server))
    {
        log_error("no worker in the list");
    _e1:
        return -1;
    }

    for (struct list_item* item = server->__worker.head; NULL != item; item = item->next)
    {
        struct net_worker* worker = container_of(item, struct net_worker, __item);

        if (-1 == net_worker_run(worker))
        {
            log_error("function call `net_worker_run` failed");

            goto _e1;
        }
    }

    int result = pthread_create(&server->server_thread, NULL, net_server_thread_main, server);
    if (0 != result)
    {
        log_error("system call `pthread_create` failed with error %d", result);

        goto _e1;
    }

    return 0;
}

void net_faker_push_server(struct net_faker* faker, struct net_server* server)
{
    linked_list_push_item(&faker->__server, &server->__item);
}

void net_faker_remove_server(struct net_faker* faker, struct net_server* server)
{
    linked_list_remove_item(&faker->__server, &server->__item);
}

int net_faker_get_server_size(struct net_faker* faker)
{
    return linked_list_get_size(&faker->__server);
}

struct net_server* net_faker_get_top_server(struct net_faker* faker)
{
    struct list_item* item = linked_list_get_top_item(&faker->__server);
    return container_of(item, struct net_server, __item);
}

int net_faker_run(struct net_faker* faker)
{
    if (0 == net_faker_get_server_size(faker))
    {
        log_error("no server in the list");
    _e1:
        return -1;
    }

    for (struct list_item* item = faker->__server.head; NULL != item; item = item->next)
    {
        struct net_server* server = container_of(item, struct net_server, __item);

        if (-1 == net_server_run(server))
        {
            log_error("function call `net_server_run` failed");

            goto _e1;
        }
    }

    return 0;
}

struct net_faker* net_faker_create()
{
    struct net_faker* faker = calloc(1, sizeof(struct net_faker));
    if (NULL == faker)
    {
        log_error("system call `calloc` failed with error %d", errno);

        return NULL;
    }

    for (int i = 0; i < CONFIG_SERVER_SIZE; i++)
    {
        struct net_server* server = net_server_create(CONFIG_BIND_ADDRESS,
            CONFIG_LISTEN_PORT, CONFIG_SSL_ENABLE);
        if (NULL == server)
        {
            log_error("function call `net_server_create` failed");

            continue;
        }

        net_faker_push_server(faker, server);
    }

    return faker;
}

void net_faker_destroy(struct net_faker* faker)
{
    while (1)
    {
        struct net_server* server = net_faker_get_top_server(faker);
        if (NULL == server)
        {
            break;
        }

        net_faker_remove_server(faker, server);

        net_server_destroy(server);
    }

    free(faker);
}

int main(int argc, char const *argv[])
{
    SSL_library_init();

    int signums[] = { SIGINT, SIGUSR1, SIGUSR2 };
    if (-1 == signal_init(signums, sizeof(signums) / sizeof(int)))
    {
        log_error("function call `signal_init` failed");
    _e1:
        return -1;
    }

    struct net_faker* faker = net_faker_create();
    if (NULL == faker)
    {
        log_error("function call `net_faker_create` failed");

        goto _e1;
    }

    if (-1 == net_faker_run(faker))
    {
        log_error("function call `net_faker_run` failed");
    _e2:
        net_faker_destroy(faker);

        goto _e1;
    }

    sigset_t sigset = { { 0 } };

    if (-1 == sigfillset(&sigset))
    {
        log_error("system call `sigfillset` failed with error %d", errno);

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

    net_faker_destroy(faker);

    return 0;
}
