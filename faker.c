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

#define EPOLL_EVENT_SIZE                    256

#define LOG_BUFFER_SIZE                     4096

#define NET_WORKER_STATUS_READY             0
#define NET_WORKER_STATUS_EXIT              1

#define NET_CLIENT_STATUS_CONNECTED         0

#define LOG_LEVEL_DEBUG                     0
#define LOG_LEVEL_INFO                      1
#define LOG_LEVEL_WARN                      2
#define LOG_LEVEL_ERROR                     3

#define container_of(ptr, type, member)     \
    (type*)((NULL == (ptr)) ? NULL : (char*)(ptr) - offsetof(type, member))

#define log_debug(format, ...)        \
    write_log_to_file(LOG_LEVEL_DEBUG, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define log_info(format, ...)        \
    write_log_to_file(LOG_LEVEL_INFO, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define log_warn(format, ...)        \
    write_log_to_file(LOG_LEVEL_WARN, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define log_error(format, ...)        \
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
    struct linked_list __send_list;
    struct linked_list __receive_list;
    struct list_item __item;
};

struct net_worker
{
    int listen_socket;
    int worker_status;
    int epoll_handle;
    pthread_t worker_thread;
    struct linked_list __client_list;
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

int set_socket_nonblock(int socket)
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

struct net_client* net_client_create(int client_socket)
{
    struct net_client* client = calloc(1, sizeof(struct net_client));
    if (NULL == client)
    {
        log_error("system call `calloc` failed with error %d", errno);

        return NULL;
    }

    client->client_socket = client_socket;
    client->client_status = NET_CLIENT_STATUS_CONNECTED;

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

int net_client_get_remaining_time(struct net_client* client)
{
    return client->expire_time - system_get_time();
}

void net_client_reset_expire_time(struct net_client* client)
{
    client->expire_time = system_get_time() + CONFIG_CLIENT_DEFAULT_TIMEOUT;
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

int net_client_handle_data(struct net_client* client)
{
    while (1)
    {
        struct net_buffer* buffer = net_client_get_receive_buffer(client);
        if (NULL == buffer)
        {
            break;
        }

        log_debug("%s", buffer->data_ptr);

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

            log_error("system call `recv` failed with error %d", errno);

            goto _e1;
        }

        buffer->data_size = length;

        net_client_add_receive_buffer(client, buffer);
    }

    if (-1 == net_client_handle_data(client))
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

struct net_worker* net_worker_create(int listen_socket)
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

    struct epoll_event event = { 0 };
    event.data.fd = listen_socket;
    event.events = EPOLLIN | EPOLLET;

    if (-1 == epoll_ctl(worker->epoll_handle, EPOLL_CTL_ADD, listen_socket, &event))
    {
        log_error("system call `epoll_ctl` failed with error %d", errno);

        close(worker->epoll_handle);
        goto _e2;
    }

    worker->listen_socket = listen_socket;
    worker->worker_status = NET_WORKER_STATUS_READY;

    log_debug("worker 0x%08X is created", worker);

    return worker;
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

void net_worker_close_client(struct net_worker* worker, struct net_client* client)
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

        net_worker_close_client(worker, client);
    }

    return -1;
}

int net_worker_accept_new_client(struct net_worker* worker)
{
    while (1)
    {
        int client_socket = accept(worker->listen_socket, NULL, NULL);
        if (-1 == client_socket)
        {
            break;
        }

        struct net_client* client = net_client_create(client_socket);
        if (NULL == client)
        {
            log_error("function call `net_client_create` failed");
        _e1:
            close(client_socket);
            continue;
        }

        struct epoll_event event = { 0 };
        event.data.ptr = client;
        event.events = EPOLLIN | EPOLLET;

        if (-1 == epoll_ctl(worker->epoll_handle, EPOLL_CTL_ADD, client_socket, &event))
        {
            log_error("system call `epoll_ctl` failed with error %d", errno);
        _e2:
            net_client_destroy(client);
            goto _e1;
        }

        client->registered_event = event.events;

        if (-1 == set_socket_nonblock(client_socket))
        {
            log_error("function call `set_socket_nonblock` failed");

            goto _e2;
        }

        net_client_reset_expire_time(client);

        net_worker_add_client(worker, client);

        log_debug("new client 0x%08X with socket %d is connected", client, client_socket);
    }

    return (EAGAIN == errno) ? 0 : -1;
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
            net_worker_close_client(worker, client);
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
    }
}

void* net_worker_thread_main(void* args)
{
    struct net_worker* worker = (struct net_worker*)args;

    struct sigaction action = { { 0 } };
    if (-1 == sigfillset(&action.sa_mask))
    {
        log_error("system call `sigfillset` failed with error %d", errno);
    _e1:
        return NULL;
    }
    
    action.sa_sigaction = net_worker_signal_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART;

    int signums[] = { SIGINT, SIGUSR1, SIGUSR2 };
    for (int i = 0; i < sizeof(signums) / sizeof(int); i++)
    {
        if (-1 == sigaction(signums[i], &action, NULL))
        {
            log_error("system call `sigaction` failed with error %d", errno);

            goto _e1;
        }
    }

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
            if (events[i].data.fd == worker->listen_socket)
            {
                net_worker_accept_new_client(worker);
                continue;
            }

            net_worker_handle_client_event(worker, &events[i]);
        }
    }

    log_debug("worker 0x%08X is exited with status %d", worker, worker->worker_status);

    return NULL;
}

void net_worker_destroy(struct net_worker* worker)
{
    while (1)
    {
        struct net_client* client = net_worker_get_client(worker);
        if (NULL == client)
        {
            break;
        }

        net_worker_remove_client(worker, client);

        net_worker_close_client(worker, client);
    }

    epoll_ctl(worker->epoll_handle, EPOLL_CTL_DEL, worker->listen_socket, NULL);

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

int main(int argc, char const *argv[])
{
    int listen_socket = create_listen_socket_and_bind("0.0.0.0", 9999);
    if (-1 == listen_socket)
    {
        log_error("function call `create_listen_socket_and_bind` failed");
    _e1:
        return -1;
    }

    struct net_worker* worker = net_worker_create(listen_socket);
    if (NULL == worker)
    {
        log_error("function call `net_worker_create` failed");
    _e2:
        close(listen_socket);
        goto _e1;
    }

    sigset_t sigset = { { 0 } };

    if (-1 == sigfillset(&sigset))
    {
        log_error("system call `sigfillset` failed with error %d", errno);

        goto _e2;
    }

    int result = pthread_create(&worker->worker_thread, NULL, net_worker_thread_main, worker);

    if (0 != result)
    {
        log_error("system call `pthread_create` failed with error %d", result);

        net_worker_destroy(worker);
        goto _e2;
    }

    while (1)
    {
        int signum = 0;
        if (0 != sigwait(&sigset, &signum))
        {
            continue;
        }

        union sigval sig_data = { .sival_ptr = worker };
        pthread_sigqueue(worker->worker_thread, signum, sig_data);

        if (SIGINT == signum)
        {
            break;
        }
    }

    pthread_join(worker->worker_thread, NULL);

    net_worker_destroy(worker);

    close(listen_socket);

    return 0;
}