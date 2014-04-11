#ifndef _GPRS_VGSN_H
#define _GPRS_VGSN_H

#include <stdint.h>
#include <curl/curl.h>

#include <openbsc/gprs_sgsn.h>

#define REST_REMOTE_URL_LENGTH 512

struct vgsn_rest_ctx {
	struct llist_head list;
	uint32_t id;
	char remote_url[REST_REMOTE_URL_LENGTH];
	CURL *curl;
};

struct vgsn_rest_ctx *vgsn_rest_ctx_alloc(uint32_t id);
struct vgsn_rest_ctx *vgsn_rest_ctx_by_id(uint32_t id);
struct vgsn_rest_ctx *vgsn_rest_ctx_find_alloc(uint32_t id);

void vgsn_rest_ctx_init(struct vgsn_rest_ctx *rc);

int vgsn_rest_delete_context_req(
		struct vgsn_rest_ctx *rest,
		struct sgsn_pdp_ctx *pctx);

int vgsn_rest_create_context_req(
		struct vgsn_rest_ctx *rest, 
		struct pdp_t *pdp, 
		struct sgsn_pdp_ctx *pctx);

extern struct llist_head vgsn_rest_ctxts;

#endif
