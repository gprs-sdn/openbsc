/* GPRS vGSN functionality */

/**
 * Jan Skalny <jan@skalny.sk>
 */

#include <stdint.h>
#include <curl/curl.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_vgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/sgsn.h>
#include <openbsc/curl.h>

#include "nxjson.h"

#include <pdp.h>

LLIST_HEAD(vgsn_rest_ctxts);

/* REST contexts */

struct vgsn_rest_ctx *vgsn_rest_ctx_alloc(uint32_t id)
{
	struct vgsn_rest_ctx *rc;

	rc = talloc_zero(tall_bsc_ctx, struct vgsn_rest_ctx);
	if (!rc)
		return NULL;

	rc->id = id;
	rc->curl = 0;
	//TODO: cleanup somewhere

	llist_add(&rc->list, &vgsn_rest_ctxts);

	return rc;
}

struct vgsn_rest_ctx *vgsn_rest_ctx_by_id(uint32_t id)
{
	struct vgsn_rest_ctx *rc;

	llist_for_each_entry(rc, &vgsn_rest_ctxts, list) {
		if (id == rc->id)
			return rc;
	}
	return NULL;
}

struct vgsn_rest_ctx *vgsn_rest_ctx_find_alloc(uint32_t id)
{
	struct vgsn_rest_ctx *rc;

	rc = vgsn_rest_ctx_by_id(id);
	if (!rc)
		rc = vgsn_rest_ctx_alloc(id);
	return rc;
}

void vgsn_rest_ctx_init(struct vgsn_rest_ctx *rc) {
	if (!rc) {
		LOGP(DGPRS, LOGL_ERROR, "Initializing invalid REST context!\n");
		return;
	}

	// cleanup
	if (rc->curl) 
		curl_conn_destroy(rc->curl);

	// create new curl connection
	rc->curl = curl_conn_create();
	if (!rc->curl) {
		LOGP(DGPRS, LOGL_ERROR, "Initializing invalid REST context!\n");
		return;
	}
}

int vgsn_rest_delete_context_req(
		struct vgsn_rest_ctx *rest,
		struct sgsn_pdp_ctx *pctx)
{
	//XXX: inform controller
	return 0;	
}


/**
 * Callback indicating finished vgsn_rest_create_context_req execution
 */
void vgsn_rest_create_context_cb(struct curl_conn *conn, struct curl_buf *buf, void *ctx)
{
	const nx_json *json;
	const nx_json *json_address, *json_dns1, *json_dns2;

	if (!conn || !buf) {
		LOGP(DGPRS, LOGL_ERROR, "vgsn_rest_create_context_cb: invalid buffer\n");
		return;
	}

	// parse buffer content
	// response should contain valid JSON with one object containint at least
	// address and dns1 string variables
	json = nx_json_parse(buf->data, 0);
	if (!json) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: invalid response\n");
		return;
	}

	json_address = nx_json_get(json, "address");
	json_dns1 = nx_json_get(json, "dns1");
	json_dns2 = nx_json_get(json, "dns2");
	
	if (json_address->type != NX_JSON_STRING) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: no IP address received\n");
		return;
	}
	
	LOGP(DGPRS, LOGL_ERROR, "REST response: address=%s dns1=%s dns2=%s\n", 
			json_address->text_value, json_dns1->text_value, json_dns2->text_value);

	//TODO: send response upon successful retrieval to 
	// static int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
}

/**
 * PDP context activation request
 */
int vgsn_rest_create_context_req(
		struct vgsn_rest_ctx *rest, 
		struct pdp_t *pdp, 
		struct sgsn_pdp_ctx *pctx) 
{
	char req[REST_REMOTE_URL_LENGTH+400];
	struct sgsn_mm_ctx *mm;

	LOGP(DGPRS, LOGL_NOTICE, "Creating PDP context via REST interface (%s)\n", 
			rest->remote_url);

	if (!pctx || !pctx->mm) {
		LOGP(DGPRS, LOGL_ERROR, "PDP context invalid!");
		return -1;
	}
	mm = pctx->mm;

	// create our REST request
	snprintf(req, sizeof(req)-1, "%s?gprs/pdp/add&bvci=%u&tlli=%x&sapi=%u&nsapi=%u&rai=%u-%u-%u-%u&apn=%s", 
			rest->remote_url,
			mm->bvci,
			mm->tlli,
			pctx->sapi, 
			pctx->nsapi,
			mm->ra.mcc, mm->ra.mnc, mm->ra.lac, mm->ra.rac,
			pdp->apn_use.v+1	//XXX: dirty, make some validation / apn_use.l
			);

	// execute this request
	// vgsn_rest_create_context_cb will handle the results
	if (!curl_get(rest->curl, req, &vgsn_rest_create_context_cb, pctx)) 
		return -1;

	return 0;
}

