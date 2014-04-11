#ifndef _CURL_H
#define _CURL_H

/**
 * receive buffers
 */
#define CURL_INITIAL_BUFFER_SIZE 1024
#define CURL_MAX_BUFFER_SIZE 1024*1024
struct curl_buf {
	char *data;
	uint32_t size;
	uint32_t max_size;
};
struct curl_buf *curl_buf_create();
void curl_buf_destroy(struct curl_buf *buf);

/**
 * connection abstraction
 */
struct curl_conn {
	CURL *curl;
	//XXX: queue
};
struct curl_conn* curl_conn_create();
void curl_conn_destroy(struct curl_conn *conn);

/**
 * requests
 */
typedef void (*curl_recv_cb)(struct curl_conn*, struct curl_buf*, void*);
#if 0
struct curl_request {
	char *url;
	curl_recv_cb cb;
	void *ctx;
	char *post_data;
	uint32_t post_data_len;
};
#endif

/**
 * file transfers
 */
int curl_get(struct curl_conn *conn, char *url, curl_recv_cb cb, void *ctx);
int curl_post(struct curl_conn *conn, char *url, char *data, uint32_t len, curl_recv_cb cb, void *ctx);
void curl_work();

/**
 * internal stuff
 */
//size_t curl_on_recv_data (char *data, size_t count, size_t size, void *ctx);

#endif
