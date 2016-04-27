/**
 * GPRS vGSN functionality 
 *
 * Jan Skalny <jan@skalny.sk>
 */

#include <stdint.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_vgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/sgsn.h>
#include <openbsc/curl.h>

#include "nxjson.h"

#include <pdp.h>
#include <gtp.h>

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

/**
 * Callback for PDP context deactivation request Ack
 */
void vgsn_rest_delete_context_cb(struct curl_conn *conn, struct curl_buf *buf, void *ctx)
{
	struct sgsn_pdp_ctx *pctx = ctx;
	if (!pctx) {
		LOGP(DGPRS, LOGL_ERROR, "vgsn_rest_delete_context_cb: missing PDP context\n");
		return;
	}

	DEBUGP(DGPRS, "Received DELETE PDP CTX CONF, cause=%d\n", GTPCAUSE_ACC_REQ);

	/* Deactivate the SNDCP layer */
	sndcp_sm_deactivate_ind(&pctx->mm->llme->lle[pctx->sapi], pctx->nsapi);

	/* Confirm deactivation of PDP context to MS */
	gsm48_tx_gsm_deact_pdp_acc(pctx);

	/* unlink the now non-existing library handle from the pdp
	 * context */
	pctx->lib = NULL;

	sgsn_pdp_ctx_free(pctx);
}

/**
 * PDP context deactivation request
 */
int vgsn_rest_delete_context_req(
		struct vgsn_rest_ctx *rest,
		struct sgsn_pdp_ctx *pctx)
{
	char req[REST_REMOTE_URL_LENGTH+400];
	struct sgsn_mm_ctx *mm;

	if (!pctx || !pctx->mm) {
		LOGP(DGPRS, LOGL_ERROR, "PDP context invalid!");
		return -1;
	}
	mm = pctx->mm;

	// inform controller of our intent
	snprintf(req, sizeof(req)-1, "%sgprs/sm/cmd=del&imsi=%s&sapi=%u&nsapi=%u&rai=%u-%u-%u-%u",
			rest->remote_url,
			mm->imsi,
			pctx->sapi,
			pctx->nsapi,
			mm->ra.mcc, mm->ra.mnc, mm->ra.lac, mm->ra.rac
			);

	//TODO: ked bude controller vediet, co od neho chceme, 
	// povedzme mu, ze sme mu znicili PDP kontext...
	// if (curl_get(rest->curl, req, 0, 0))
	//	return -1;

	//XXX: maybe we should wait for some response from controller, before teardown?

	// tear down PDP context
	vgsn_rest_delete_context_cb(0, 0, pctx);

	return 0;
}

/**
 * Callback indicating finished vgsn_rest_create_context_req execution
 */
void vgsn_rest_create_context_cb(struct curl_buf *buf, void *ctx)
{
	const nx_json *json;
	const nx_json *json_address, *json_dns1, *json_dns2;
	struct sgsn_pdp_ctx *pctx = (struct sgsn_pdp_ctx*)ctx;
	struct in_addr address, dns1, dns2;
	struct ul255_t *pco;

	if (!pctx) {
		LOGP(DGPRS, LOGL_ERROR, "vgsn_rest_create_context_cb: missing PDP context\n");
		return;
	}

	if (!buf) {
		LOGP(DGPRS, LOGL_ERROR, "vgsn_rest_create_context_cb: invalid buffer\n");
		goto reject;
	}

	// parse buffer content
	// response should contain valid JSON with one object containint at least
	// address and dns1 string variables
	json = nx_json_parse(buf->data, 0);
	if (!json) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: invalid response\n");
		goto reject;
	}

	json_address = nx_json_get(json, "address");
	json_dns1 = nx_json_get(json, "dns1");
	json_dns2 = nx_json_get(json, "dns2");
	
	if (json_address->type != NX_JSON_STRING) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: no IP address received\n");
		goto reject;
	}
	
	LOGP(DGPRS, LOGL_ERROR, "REST response: address=%s dns1=%s dns2=%s\n", 
			json_address->text_value, json_dns1->text_value, json_dns2->text_value);

	// hack pctx so it looks like Create PDP Context Response from GGSN
	
	// fix pctx->lib->radio_pri;
	// leave same value as for downlink
	
	// fix pctx->lib->eua;
	inet_aton(json_address->text_value, &address);
	ipv42eua(&(pctx->lib->eua), &address);

	// fix pctx->lib->pco_req
	pco = &(pctx->lib->pco_req);
	pco->l = 20;
	pco->v[0] = 0x80;	/* x0000yyy x=1, yyy=000: PPP */
	pco->v[1] = 0x80;	/* IPCP */
	pco->v[2] = 0x21;
	pco->v[3] = 0x10;	/* Length of contents */
	pco->v[4] = 0x02;	/* ACK */
	//pco->v[5] = 0x00;	/* ID: Need to match request */
	pco->v[6] = 0x00;	/* Length */
	pco->v[7] = 0x10;
	pco->v[8] = 0x81;	/* DNS 1 */
	pco->v[9] = 0x06;
	inet_aton(json_dns1->text_value, &dns1);
	memcpy(&pco->v[10], &dns1, sizeof(dns1));
	pco->v[14] = 0x83;
	pco->v[15] = 0x06; /* DNS 2 */
	inet_aton(json_dns2->text_value, &dns2);
	memcpy(&pco->v[16], &dns2, sizeof(dns2));

	// activate the SNDCP layer
	sndcp_sm_activate_ind(&pctx->mm->llme->lle[pctx->sapi], pctx->nsapi);

	// send modified GTP message to MS
	LOGP(DGPRS, LOGL_NOTICE, "SENDING ACTIVATE PDP CTX ACCEPT FROM REST CB IN vgsn.c\n");
	gsm48_tx_gsm_act_pdp_acc(pctx);
	return;

reject:
	/*
	 * In case of a timeout pdp will be NULL but we have a valid pointer
	 * in pctx->lib. For other rejects pctx->lib and pdp might be the
	 * same.
	 */
	pctx->state = PDP_STATE_NONE;
	if (pctx->lib)
		pdp_freepdp(pctx->lib);
	pctx->lib = NULL;

	/* Send PDP CTX ACT REJ to MS */
	gsm48_tx_gsm_act_pdp_rej(pctx->mm, pctx->ti, GSM_CAUSE_NET_FAIL, 0, NULL);
	sgsn_pdp_ctx_free(pctx);
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

	if (!pctx || !pctx->mm) {
		LOGP(DGPRS, LOGL_ERROR, "PDP context invalid!");
		return -1;
	}
	mm = pctx->mm;

	// create our REST request
	//XXX change PDP to SM
	snprintf(req, sizeof(req)-1, "%sgprs/sm/cmd=add&imsi=%s&bvci=%u&tlli=%08x&sapi=%u&nsapi=%u&rai=%u-%u-%u-%u&apn=%s&drx_param=%04x", 
			rest->remote_url,
			mm->imsi,
			mm->bvci,
			mm->tlli,
			pctx->sapi, 
			pctx->nsapi,
			mm->ra.mcc, mm->ra.mnc, mm->ra.lac, mm->ra.rac,
			pdp->apn_use.v+1,	//XXX: dirty, make some validation / apn_use.l
			mm->drx_parms		//XXX: FIXME: mm->drx_params is invalid?? 
			);

	// execute this request
	// vgsn_rest_create_context_cb will handle the results
	if (curl_get(rest->curl, req, &vgsn_rest_create_context_cb, (void *) pctx, 0, 0)) 
		return -1;

	return 0;
}

/**
 * Callback indicating finished vgsn_rest_attach_req execution
 */
void vgsn_rest_attach_cb(struct curl_buf *buf, void *ctx, void *msg, void *att_type)
{
	const nx_json *json, *json_imsi, *json_ptmsi, *json_attach_type, *json_attach_result;
	struct msgb *message = (struct msgb *) msg;
	struct sgsn_mm_ctx *mmctx = (struct sgsn_mm_ctx*)ctx;

	if (!mmctx) {
		LOGP(DGPRS, LOGL_ERROR, "vgsn_rest_attach_cb: missing MM context\n");
		return;
	}

         if (!buf) {
		LOGP(DGPRS, LOGL_ERROR, "vgsn_rest_attach_cb: invalid buffer\n");
		goto reject;
	}

	// parse buffer content
	// response should contain valid JSON with one object containint at least
	// P-TMSI, IMSI should be present for verification, too
	json = nx_json_parse(buf->data, 0);
	if (!json) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: invalid response\n");
		goto reject;
	}

	json_attach_type = nx_json_get(json, "cmd");
	json_attach_result = nx_json_get(json, "result");
	
	if (json_attach_type->type != NX_JSON_STRING) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: no attach type received\n");
		goto reject;
	}

	if (json_attach_result->type != NX_JSON_STRING) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: no attach type received\n");
		goto reject;
	}
	
	//attach with IMSI
	if (! strcmp(json_attach_type->text_value, "atti")){
		
		if (! strcmp(json_attach_result->text_value, "success")){
			json_imsi = nx_json_get(json, "imsi");
			json_ptmsi = nx_json_get(json, "p-tmsi");
		}	
		//send attach reject if IMSI attach fails
		else {	
			goto reject;
		}
	}
	
	//attach with P-TMSI
	else if (! strcmp(json_attach_type->text_value, "attp")){
		if (! strcmp(json_attach_result->text_value, "success")){
			json_imsi = nx_json_get(json, "imsi");
			json_ptmsi = nx_json_get(json, "p-tmsi");
		}
		//try attach with IMSI if attach with P-TMSI fails
		else {
			LOGP(DGPRS, LOGL_ERROR, "Attach with P-TMSI unsuccessful. Falling back to IMSI\n");
			goto fallback;
		}
	}
	
	//unknown attach type
	else {
		goto reject;
	}

	if (json_imsi->type != NX_JSON_STRING) {
		LOGP(DGPRS, LOGL_ERROR, "REST call failed: no IMSI received\n");
		goto reject;
	}
	
	if (json_ptmsi->type != NX_JSON_STRING) {
                LOGP(DGPRS, LOGL_ERROR, "REST call failed: no P-TMSI received\n");
                goto reject;
        }

	//insert values retrieved from controller to the MM ctx
	strncpy(mmctx->imsi, json_imsi->text_value, sizeof(mmctx->imsi));
	mmctx->p_tmsi_old = mmctx->p_tmsi;
	mmctx->p_tmsi = strtol(json_ptmsi->text_value, 0, 0);
	
	LOGP(DGPRS, LOGL_ERROR, "REST response: imsi=%s p-tmsi=%x\n", mmctx->imsi, mmctx->p_tmsi);
	LOGP(DGPRS, LOGL_ERROR, "REST response: length of p-tmsi: %d\n", strlen(json_ptmsi->text_value));
	
	/* Even if there is no P-TMSI allocated, the MS will switch from
	* foreign TLLI to local TLLI */
	mmctx->tlli_new = gprs_tmsi2tlli(mmctx->p_tmsi, TLLI_LOCAL);

	/* Inform LLC layer about new TLLI but keep old active */
	gprs_llgmm_assign(mmctx->llme, mmctx->tlli, mmctx->tlli_new, GPRS_ALGO_GEA0, NULL);

fallback:
	//get other subscriber info (IMSI/IMEI)
	gsm48_gmm_authorize(mmctx, GMM_T3350_MODE_ATT);
	return;

reject:
	//XXX free the MM ctx	
	LOGP(DGPRS, LOGL_ERROR, "REST ATTACH REQUEST denied\n");
	//gsm48_tx_gmm_att_rej_oldmsg(message,GMM_CAUSE_GPRS_NOTALLOWED);
	gsm48_tx_gmm_att_rej(mmctx, GMM_CAUSE_MS_ID_NOT_DERIVED);
	LOGP(DGPRS, LOGL_ERROR, "gsm48_tx_gmm_att_rej_oldmsg executed\n");
}

/**
* Attach request
*/
int vgsn_rest_attach_req(
		struct vgsn_rest_ctx *rest,
		struct sgsn_mm_ctx *ctx,
		uint8_t mi_type, 
		struct msgb *msg
)
{	
	char req[REST_REMOTE_URL_LENGTH+400];

	if (!ctx) {
                LOGP(DGPRS, LOGL_ERROR, "MM context invalid!");
                return -1;
	}	

	LOGP(DGPRS, LOGL_NOTICE, "Sending attach request via REST interface (%s)\n", rest->remote_url);
	
	switch (mi_type) {

	case GSM_MI_TYPE_IMSI:
		
		snprintf(req, sizeof(req)-1, "%sgprs/gmm/cmd=atti&imsi=%s",
			rest->remote_url,
			ctx->imsi
			);
		break;

	case GSM_MI_TYPE_TMSI:
		snprintf(req, sizeof(req)-1, "%sgprs/gmm/cmd=attp&p-tmsi=0x%08x&rai=%u-%u-%u-%u",
			rest->remote_url,
			ctx->p_tmsi,
			ctx->ra_old.mcc, ctx->ra_old.mnc, ctx->ra_old.lac, ctx->ra_old.rac       
			);
        	break;	
	
	default:
		return -1;
	}
	
	//execute the request
	if (curl_get(rest->curl, req, &vgsn_rest_attach_cb, (void *) ctx, (void *) msg, 0))
                return -1;
	return 0;
}

/**
 * Callback indicating finished vgsn_rest_detach_req execution
 */
void vgsn_rest_detach_cb()
{	
	return;
}

/**
* Detach request
*/
int vgsn_rest_detach_req(struct vgsn_rest_ctx *rest,
	                 struct sgsn_mm_ctx *ctx)
{	
	char req[REST_REMOTE_URL_LENGTH+400];
	
	if (!ctx){
		LOGP(DGPRS, LOGL_ERROR, "MM context invalid!");
		return -1;
	}	

	LOGP(DGPRS, LOGL_NOTICE, "Sending attach request via REST interface (%s)\n", rest->remote_url);

	snprintf(req, sizeof(req)-1, "%sgprs/gmm/cmd=deti&p_tmsi=0x%08x",
                            rest->remote_url,
                            ctx->p_tmsi);

	//execute the request
	if (curl_get(rest->curl, req, &vgsn_rest_detach_cb, 0, 0, 0))
                return -1;
	return 0;
}
