/**
 * libcurl wrapper with multi-handles and queues
 *
 * Jan Skalny <jan@skalny.sk>
 */

#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/curl.h>

#include "nxjson.h"

/**
 * New data was received by CURL. 
 * Append to existing buffer (ctx)
 */
size_t curl_on_recv_data (char *data, size_t count, size_t size, void *ctx) 
{
	struct curl_buf *buf = (struct curl_buf*) ctx;
	uint32_t recv_size, new_size;

	if (!buf) {
			LOGP(DGPRS, LOGL_FATAL, "CURL no buffer supplied!\n");
			return 0;
	}

	recv_size = count*size;
	new_size = buf->size + recv_size;

	// check if we have enough space in our buffer
	if (buf->max_size <= new_size) {
		// are we even allowed to have buffer this big?
		if (new_size > CURL_MAX_BUFFER_SIZE) {
			// fail miserably
			LOGP(DGPRS, LOGL_FATAL, "CURL buffer is too small. Fail to grow!\n");
			return 0;
		}

		// resize our buffer to accomodate new data and something more
		buf->max_size = new_size + CURL_MAX_BUFFER_SIZE;
		buf->data = realloc(buf->data, buf->max_size);
		if (!buf->data) {
			LOGP(DGPRS, LOGL_FATAL, "realloc failed!\n");
			return 0;
		}
	}
	// append data to our buffer
	memcpy(buf->data+buf->size, data, recv_size);
	buf->size += recv_size;

	return recv_size;
}

static int curl_conn_event(struct osmo_fd *fd, unsigned int what)
{
	struct curl_conn *conn;
	struct curl_req *req;
	CURLMcode ret;
	CURLMsg *msg;
	long http_status_code;
	
 	conn = (struct curl_conn *)fd->data;
	if (!conn)
		return 0;

	do {
		// do, what needs to be done
		ret = curl_multi_perform(conn->mcurl, &conn->active);
	} while (ret == CURLM_CALL_MULTI_PERFORM);

	if (ret != CURLM_OK) {
		LOGP(DGPRS, LOGL_ERROR, "curl_multi_perform: failed (%u)\n", ret);
		return 0;
	}

	while ((msg = curl_multi_info_read(conn->mcurl, &conn->active))) {
		if (msg->msg != CURLMSG_DONE) {
			LOGP(DGPRS, LOGL_NOTICE, "curl_multi_info_read: unknown msg (%u)\n", msg->msg);
			continue;
		}

		// each REST interface has only one active HTTP request!
		req = curl_conn_pop_req(conn);

		// if transfer failed, invalidate request buffer
		if (msg->data.result != CURLE_OK) 
			curl_buf_cleanup(conn->buf);

		// only OK (200) is OK :)
		curl_easy_getinfo(conn->curl, CURLINFO_HTTP_CODE, &http_status_code);
		if (http_status_code != 200) {
			LOGP(DGPRS, LOGL_ERROR, "curl_get: HTTP status code %lu\n", 
					http_status_code);
			curl_buf_cleanup(conn->buf);

		// make sure everything is null-terminated -- hack-n-slash
		} else if (curl_on_recv_data("\0", 1, 1, conn->buf) != 1) {
			LOGP(DGPRS, LOGL_ERROR, "curl_get: append('\\0') failed\n");
			curl_buf_cleanup(conn->buf);

		// if everything went well, we should have something in our buffer
		} else if (!conn->buf->data || conn->buf->size == 0) {
			LOGP(DGPRS, LOGL_NOTICE, "curl_get: nothing received\n");
			curl_buf_cleanup(conn->buf);
		}

		// either way, we need to execute callback function for this request
		if (req->cb) 
			(*req->cb)(conn->buf, req->arg1, req->arg2, req->arg3);
	
		// destroy old request and remove easy-handle from multi-handle
		// (bug in libcurl multi interface)
		curl_req_destroy(req);
		curl_multi_remove_handle(conn->mcurl, conn->curl);
		if (conn->fd.fd >= 0) {
			osmo_fd_unregister(&conn->fd);
			conn->fd.fd = -1;
		}

		// schedule next request, if we have one
		curl_conn_start_next_req(conn);
	}

	return 0;
}


/**
 * Create new CURL receive buffer
 * Used by CURLOPT_WRITEDATA opt for data retrieval.
 */
struct curl_buf *curl_buf_create() 
{
	struct curl_buf *buf;

	buf = (struct curl_buf*) malloc(sizeof(struct curl_buf));
	buf->size = 0;
	buf->max_size = CURL_INITIAL_BUFFER_SIZE;
	buf->data = malloc(buf->max_size);

	return buf;
}

/**
 * Destroy CURL receive buffer
 */
void curl_buf_destroy(struct curl_buf *buf) 
{
	if (!buf)
		return;
	if (buf->data)
		free(buf->data);
  free(buf);
}

/**
 * Cleanup receive buffer adn prepare for reuse
 */
void curl_buf_cleanup(struct curl_buf *buf)
{
	if (!buf)
		return;
	buf->size = 0;
	*buf->data = 0;
}

void xtest(struct curl_buf *buf, void *x) {
	LOGP(DGPRS, LOGL_ERROR, "xtest results: x=%p buf=%s\n", x, buf->data);
}

/**
 * Create new CURL connection abstraction
 */
struct curl_conn * curl_conn_create()
{
	struct curl_conn *conn;

	LOGP(DGPRS, LOGL_NOTICE, "curl_conn_create\n");

	conn = (struct curl_conn*)malloc(sizeof(struct curl_conn));
	if (!conn) 
		return 0;

	INIT_LLIST_HEAD(&conn->queue);

	conn->fd.fd = -1;
	conn->fd.data = conn;
	conn->fd.when = BSC_FD_READ|BSC_FD_WRITE|BSC_FD_EXCEPT;
	conn->fd.cb = curl_conn_event;

	conn->active = 0;
	conn->mcurl = curl_multi_init();
	conn->curl = curl_easy_init();
	conn->buf = curl_buf_create();

	// callback function to fill our output buffer
	curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, curl_on_recv_data);
	curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, conn->buf);

	// generic curl options
	//XXX: ssl goes here
	curl_easy_setopt(conn->curl, CURLOPT_FOLLOWLOCATION, 1);

#if 0
	// async test
	curl_get(conn, "http://netvor.sk/j/t/rest.php?gprs/pdp/add&bvci=2&tlli=d2818615&sapi=3&nsapi=5&rai=901-70-1-0&apn=internet", &xtest, 42);
	curl_get(conn, "http://netvor.sk/j/t/rest.php?gprs/pdp/add&bvci=2&tlli=2818615&sapi=3&nsapi=5&rai=901-70-1-0&apn=internet", &xtest, 42);
	curl_get(conn, "http://netvor.sk/j/t/rest.php?gprs/pdp/add&bvci=2&tlli=818615&sapi=3&nsapi=5&rai=901-70-1-0&apn=internet", &xtest, 42);
	curl_get(conn, "http://netvor.sk/j/t/rest.php?gprs/pdp/add&bvci=2&tlli=18615&sapi=3&nsapi=5&rai=901-70-1-0&apn=internet", &xtest, 42);
	curl_get(conn, "http://netvor.sk/j/t/rest.php?gprs/pdp/add&bvci=2&tlli=8615&sapi=3&nsapi=5&rai=901-70-1-0&apn=internet", &xtest, 42);
#endif

	return conn;
}



/**
 * Destroy CURL connection
 */
void curl_conn_destroy(struct curl_conn *conn) 
{
	if (!conn)
		return;

	if (conn->curl)
		curl_easy_cleanup(conn->curl);
	if (conn->mcurl)
		curl_multi_cleanup(conn->mcurl);

	free(conn);
}

/**
 * Queue up GET request to given connection
 * 
 * @returns 0 on success
 */
int curl_get(struct curl_conn *conn, char *url, curl_recv_cb *cb, void *arg1, void *arg2, void *arg3)
{
	struct curl_req *req;

	LOGP(DGPRS, LOGL_NOTICE, "curl_get: %s\n", url);

	// create new request 
	req = curl_req_create(url, cb, arg1, arg2, arg3, 0, 0);
	if (!req) {
		LOGP(DGPRS, LOGL_ERROR, "failed to create new request\n");
		return -1;
	}

	// and push it back into queue, and try to run it
	curl_conn_push_req(conn, req);
	curl_conn_start_next_req(conn);

	return 0;
}

void curl_conn_start_next_req(struct curl_conn *conn)
{
	struct curl_req *req;
	struct llist_head *lh;
	int fd, max_fd=0;
	fd_set fdr, fdw, fde;
 
	// lets bail out, ...
	if (!conn || !conn->curl | !conn->mcurl) 
		return;

	// ... if we don't have anything in queue
	if (llist_empty(&conn->queue)) {
		//LOGP(DGPRS, LOGL_DEBUG, "conn queue is empty\n");
		return;
	}

	// ... or something is already active
	if (conn->active) {
		//LOGP(DGPRS, LOGL_DEBUG, "conn queue is already active\n");
		return;
	}

	lh = conn->queue.next;
	req = llist_entry(lh, struct curl_req, entry);

	// cleanup receive buffer first
	curl_buf_cleanup(conn->buf);

	// set new URL for easy-handle
	curl_easy_setopt(conn->curl, CURLOPT_URL, req->url);

	// (re)-add easy handle to our multi-handle
	curl_multi_add_handle(conn->mcurl, conn->curl);

	// exec
	curl_multi_perform(conn->mcurl, &conn->active);

	if (conn->active == 0) {
		// our request might have already ended (eg. failed resolver)
		curl_conn_event(&conn->fd, BSC_FD_READ);
		return;
	}

	// find our file descriptor 
	FD_ZERO(&fdr);
	FD_ZERO(&fdw);
	FD_ZERO(&fde);
	curl_multi_fdset(conn->mcurl, &fdr, &fdw, &fde, &max_fd);

	// something died in libcurl?
	if (max_fd == -1) {
		LOGP(DGPRS, LOGL_ERROR, "curl_multi_fdset: max_fd=-1\n");
		exit(1);
	}
		
	// initialize callback
	for (fd=0; fd<=max_fd; fd++) {
		if (FD_ISSET(fd, &fdr) || 
				FD_ISSET(fd, &fdw) ||
				FD_ISSET(fd, &fde)) {
			conn->fd.fd = fd;
			osmo_fd_register(&conn->fd);
			return;
		}
	}
}

void curl_conn_push_req(struct curl_conn *conn, struct curl_req *req)
{
	llist_add_tail(&req->entry, &conn->queue);
}

struct curl_req * curl_conn_pop_req(struct curl_conn *conn)
{
	struct llist_head *lh;

	if (llist_empty(&conn->queue)) 
		return NULL;

	lh = conn->queue.next;
	llist_del(lh);
	return llist_entry(lh, struct curl_req, entry);
}

struct curl_req *curl_req_create(char *url, curl_recv_cb *cb, void *arg1, void *arg2, void *arg3, char *post_data, uint32_t post_data_len)
{
	struct curl_req *req;

	req = (struct curl_req*) malloc(sizeof(struct curl_req));
	if (!req)
		return 0;

	INIT_LLIST_HEAD(&req->entry);
	req->url = strdup(url);
	req->cb = cb;
	req->arg1 = arg1;
	req->arg2 = arg2;
	req->arg3 = arg3;
	//XXX: maybe we should duplicate this request instead...
	req->post_data = post_data;
	req->post_data_len = post_data_len;

	return req;
}

void curl_req_destroy(struct curl_req *req)
{
	if (!req)
		return;
	if (req->url)
		free(req->url);
	if (req->post_data)
		free(req->post_data);
	free(req);
}

