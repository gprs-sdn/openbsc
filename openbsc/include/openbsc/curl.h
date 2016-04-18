#ifndef _CURL_H
#define _CURL_H

struct osmo_fd;

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
void curl_buf_cleanup(struct curl_buf *buf);

/**
 * connection abstraction
 */
struct curl_conn {
	struct llist_head queue;
	int active;
	CURLM *mcurl;
	CURL *curl;
	struct curl_buf *buf;
	struct osmo_fd fd;
};
struct curl_conn* curl_conn_create();
void curl_conn_destroy(struct curl_conn *conn);

/**
 * requests
 */
typedef void (curl_recv_cb)(struct curl_buf*, void*, void*, void*);
struct curl_req {
	struct llist_head entry;
	char *url;
	curl_recv_cb *cb;
	void *arg1;
	void *arg2;
	void *arg3;
	char *post_data;
	uint32_t post_data_len;
};
struct curl_req *curl_req_create(char *url, curl_recv_cb *cb, void *arg1, void *arg2, void *arg3, char *post_data, uint32_t post_data_len);
void curl_req_destroy(struct curl_req *req);

/**
 * file transfers
 */
int curl_get(struct curl_conn *conn, char *url, curl_recv_cb *cb, void *arg1, void *arg2, void *arg3);
#if 0
int curl_post(struct curl_conn *conn, char *url, char *data, uint32_t len, curl_recv_cb *cb, void *ctx);
#endif

/**
 * internal stuff
 */
void curl_conn_push_req(struct curl_conn *conn, struct curl_req *req);
struct curl_req * curl_conn_pop_req(struct curl_conn *conn);
void curl_conn_start_next_req(struct curl_conn *conn);
//size_t curl_on_recv_data (char *data, size_t count, size_t size, void *ctx);

#endif
