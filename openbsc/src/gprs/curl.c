/**
 * libcurl wrapper with multi-handles and queues
 */

#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
 * Create new CURL connection abstraction
 */
struct curl_conn * curl_conn_create()
{
	struct curl_conn *conn;

	conn = (struct curl_conn*)malloc(sizeof(struct curl_conn));
	if (!conn) 
		return 0;

	conn->curl = curl_easy_init();
	curl_easy_setopt(conn->curl, CURLOPT_FOLLOWLOCATION, 1);
	//XXX: more initialization

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
	//XXX: more cleanup

	free(conn);
}

/**
 * Queue up GET request to given connection
 * 
 * @returns 0 on success
 */
int curl_get(struct curl_conn *conn, char *url, curl_recv_cb cb, void *ctx)
{
	struct curl_buf *buf = NULL;
	CURLcode res;
	long http_status_code;

	if (!conn || !conn->curl)
		goto err;

	buf = curl_buf_create();
	if (!buf)
		goto err;

	curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, curl_on_recv_data);
	curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, buf);
	curl_easy_setopt(conn->curl, CURLOPT_URL, url);

	//XXX: async 
	res = curl_easy_perform(conn->curl);
	if(res != CURLE_OK) {
		LOGP(DGPRS, LOGL_ERROR, "curl_get: curl_easy_perform: %s\n", 
				curl_easy_strerror(res));
		goto err;
	}

	// only OK (200) is OK :)
	curl_easy_getinfo(conn->curl, CURLINFO_HTTP_CODE, &http_status_code);
	if (http_status_code != 200) {
		LOGP(DGPRS, LOGL_ERROR, "curl_get: HTTP status code %lu\n", 
				http_status_code);
		goto err;
	}

	// make sure everything is null-terminated -- hack-n-slash
	if (curl_on_recv_data("\0", 1, 1, buf) != 1) {
		LOGP(DGPRS, LOGL_ERROR, "curl_get: append('\\0') failed\n");
		goto err;
	}
	
	// if everything went well, we should have something in our buffer
	if (!buf->data || buf->size == 0) {
		LOGP(DGPRS, LOGL_NOTICE, "curl_get: nothing received\n");
		goto err;
	}

	goto ok;
err:
	// something broke.. destroy possibly invalid data 
	if (buf)
		curl_buf_destroy(buf);
	buf = 0;

ok:
	// either way, execute given callback function
	cb(conn, buf, ctx);

	// cleanup
	if (buf) {
		curl_buf_destroy(buf);
	}
	//XXX: destroy request

	return 0;
}

void curl_work()
{
	// done! :)
}

