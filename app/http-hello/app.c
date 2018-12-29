// SPDX-License-Identifier: MIT

#include "../../arch/x86/rtc.h"
#include "blk.h"
#include "init.h"
#include "kalloc.h"
#include "mem.h"
#include "net/http_parser.h"
#include "net/tcp.h"
#include "stdio.h"
#include "string.h"
#include "timer.h"

struct myserver_data {
    struct http_parser http_parser;
    struct http_parser_settings http_parser_settings;
};

static int myserver_http_message_begin(UNUSED http_parser *parser) { return 0; }

#define MYSERVER_HELLO_RESPONSE "Hello, world!"

#define MYSERVER_HELLO_HTTP_RESPONSE    \
    "HTTP/1.1 200 OK\r\n"               \
    "Server: Unicycle Http Service\r\n" \
    "Content-Length: 48\r\n"            \
    "Content-Type: text/html\r\n"       \
    "Connection: Closed\r\n"            \
    "\r\n"                              \
    "<html>"                            \
    "<body>"                            \
    "<h1>Hello, World!</h1>"            \
    "</body>"                           \
    "</html>"

#define MYSERVER_FILE_NOT_FOUND         \
    "HTTP/1.1 404 Not Found\r\n"        \
    "Server: Unicycle Http Service\r\n" \
    "Content-Length: 0\r\n"             \
    "Connection: Closed\r\n"            \
    "\r\n"

static int myserver_http_on_url(http_parser *parser, const char *at, size_t length) {
    const char *response;
    size_t response_len;

    IFVV printf("myserver_http_on_url: %.*s\n", (int)length, at);
    if (!strncmp(at, "/", length)) {
        // If it the the main page request then return hello world
        response = MYSERVER_HELLO_HTTP_RESPONSE;
        response_len = sizeof(MYSERVER_HELLO_HTTP_RESPONSE) - 1;
    } else if (!strncmp(at, "/hello.txt", length)) {
        // If it the the main page request then return hello world
        response = MYSERVER_HELLO_RESPONSE;
        response_len = sizeof(MYSERVER_HELLO_RESPONSE) - 1;
    } else {
        // error 404 otherwise
        response = MYSERVER_FILE_NOT_FOUND;
        response_len = sizeof(MYSERVER_FILE_NOT_FOUND) - 1;
    }

    struct tcp_connection *conn = parser->data;

    // send HTTP response
    buffer_t *out = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_TCP);
    memcpy(out->pos, response, response_len);
    out->data_size += response_len;
    tcp_send(conn, out);
    return 0;
}

static int myserver_http_message_complete(UNUSED http_parser *parser) { return 0; }

static bool myserver_accept(struct tcp_connection *conn) {
    IFVV printf("Accepting a TCP connection from " IPADDR_PRINT_FMT ":%u\n", IPADDR_PRINT_PARAMS(conn->remote_ip), conn->remote_port);

    struct myserver_data *data = kalloc(struct myserver_data);
    http_parser_init(&data->http_parser, HTTP_REQUEST);
    http_parser_settings_init(&data->http_parser_settings);

    data->http_parser_settings.on_message_begin = myserver_http_message_begin;
    data->http_parser_settings.on_url = myserver_http_on_url;
    data->http_parser_settings.on_message_complete = myserver_http_message_complete;
    data->http_parser.data = conn;

    conn->user_data = data;
    return true;
}

static void myserver_receive(struct tcp_connection *conn, buffer_t *buff) {
    struct myserver_data *data = conn->user_data;
    http_parser_execute(&data->http_parser, &data->http_parser_settings, buff->pos, buffer_data_available(buff));
    buffer_free(buff);
}

static void myserver_finish(struct tcp_connection *conn) {
    IFVV printf("Finishing TCP connection from " IPADDR_PRINT_FMT ":%u\n", IPADDR_PRINT_PARAMS(conn->remote_ip), conn->remote_port);
    kfree((struct myserver_data *)conn->user_data);
    tcp_close(conn);
}

const struct tcp_ops myserver = {
    .accept = myserver_accept,
    .receive = myserver_receive,
    .finish = myserver_finish,
};

#define MYSERVER_PORT 80

static void myserver_bind(struct ip4if *ip4if) { tcp_bind(ip4if, MYSERVER_PORT, &myserver); }

static void blk_op_complete(UNUSED struct blk_device *blk, void *data, enum blk_op_status status, UNUSED void *context) {
    printf("Blk write complete, status=%d\n", status);
    kfree_size(data, 512);
}

size_t counter = 0;

static void timer_fire(UNUSED void *data) {
    struct rtc_date date;
    rtc_read(&date);

    printf("Hello from timer #%ld. Today's date is %d-%d-%d %d-%d-%d\n", (uint64_t)data, date.year, date.month, date.day, date.hours,
           date.minutes, date.seconds);

    struct blk_device *blk = blk_dev_get(0);

    if (blk) {
        void *data = kalloc_size(512);
        strcpy((char *)data, "Hello, test world!");
        blk_write(blk, data, 512, counter++, blk_op_complete, NULL);
    } else {
        printf("No block device found\n");
    }
}

void application_init(void) {
    ip4if_on_init(myserver_bind);
    timer_add(time_sec_from_now(1), timer_fire, (void *)1);
    timer_add(time_sec_from_now(2), timer_fire, (void *)2);
    timer_add(time_sec_from_now(3), timer_fire, (void *)3);

    struct blk_device *blk = blk_dev_get(0);

    if (blk) {
        void *data = kalloc_size(512);
        strcpy((char *)data, "Hello, NCQ world!");
        blk_write(blk, data, 512, counter++, blk_op_complete, NULL);
    } else {
        printf("No block device found\n");
    }
}
