/* GPRS vGSN functionality */

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
		curl_easy_cleanup(rc->curl);

	if (!(rc->curl = curl_easy_init())) {
		LOGP(DGPRS, LOGL_ERROR, "Initializing invalid REST context!\n");
		return;
	}
	
	curl_easy_setopt(rc->curl, CURLOPT_FOLLOWLOCATION, 1);
}

int vgsn_rest_delete_context_req(
		struct vgsn_rest_ctx *rest,
		struct sgsn_pdp_ctx *pctx)
{
	//XXX: inform controller
	return 0;	
}

int vgsn_rest_create_context_req(
		struct vgsn_rest_ctx *rest, 
		struct pdp_t *pdp, 
		struct sgsn_pdp_ctx *pctx) 
{
	char req[REST_REMOTE_URL_LENGTH+400];
	struct sgsn_mm_ctx *mm;
	CURLcode res;

	LOGP(DGPRS, LOGL_NOTICE, "Creating PDP context via REST interface (%s)\n", 
			rest->remote_url);

	if (!pctx || !pctx->mm) {
		LOGP(DGPRS, LOGL_ERROR, "PDP context invalid!");
		return 0; //XXX: return something else
	}
	mm = pctx->mm;

	snprintf(req, sizeof(req)-1, "%s?gprs/pdp/add&bvci=%u&tlli=%x&sapi=%u&nsapi=%u&rai=%u-%u-%u-%u&apn=%s", 
			rest->remote_url,
			mm->bvci,
			mm->tlli,
			pctx->sapi, 
			pctx->nsapi,
			mm->ra.mcc, mm->ra.mnc, mm->ra.lac, mm->ra.rac,
			pdp->apn_use.v+1	//XXX: dirty, make some validation / apn_use.l
			);

	curl_easy_setopt(rest->curl, CURLOPT_URL, req);

	//XXX: async
	res = curl_easy_perform(rest->curl);
	if(res != CURLE_OK) {
		LOGP(DGPRS, LOGL_ERROR, "curl_easy_perform() failed: %s\n", 
				curl_easy_strerror(res));
	}

	//TODO: send response upon successful retrieval to 
	// static int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
	//

	return 0;
}

