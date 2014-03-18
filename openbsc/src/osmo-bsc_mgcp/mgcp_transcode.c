/*
 * (C) 2014 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>


#include "../../bscconfig.h"

#include "g711common.h"
#include <gsm.h>
#ifdef HAVE_BCG729
#include <bcg729/decoder.h>
#include <bcg729/encoder.h>
#endif

#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include <osmocom/core/talloc.h>

enum audio_format {
	AF_INVALID, /* must be 0 */
	AF_S16,
	AF_L16,
	AF_GSM,
	AF_G729,
	AF_PCMA
};

struct mgcp_process_rtp_state {
	/* decoding */
	enum audio_format src_fmt;
	union {
		gsm gsm_handle;
#ifdef HAVE_BCG729
		bcg729DecoderChannelContextStruct *g729_dec;
#endif
	} src;
	size_t src_frame_size;
	size_t src_samples_per_frame;

	/* processing */

	/* encoding */
	enum audio_format dst_fmt;
	union {
		gsm gsm_handle;
#ifdef HAVE_BCG729
		bcg729EncoderChannelContextStruct *g729_enc;
#endif
	} dst;
	size_t dst_frame_size;
	size_t dst_samples_per_frame;

	int second_packet;
	int ptime_different;
	uint16_t next_seq;
	int16_t samples[10*160];
	size_t sample_cnt;
};

int mgcp_get_trans_frame_size(void *state_, int nsamples, int dst)
{
	struct mgcp_process_rtp_state *state = state_;
	if (dst)
		return (nsamples >= 0 ?
			nsamples / state->dst_samples_per_frame :
			1) * state->dst_frame_size;
	else
		return (nsamples >= 0 ?
			nsamples / state->src_samples_per_frame :
			1) * state->src_frame_size;
}

static enum audio_format get_audio_format(const struct mgcp_rtp_end *rtp_end)
{
	if (rtp_end->subtype_name) {
		if (!strcmp("GSM", rtp_end->subtype_name))
			return AF_GSM;
		if (!strcmp("PCMA", rtp_end->subtype_name))
			return AF_PCMA;
#ifdef HAVE_BCG729
		if (!strcmp("G729", rtp_end->subtype_name))
			return AF_G729;
#endif
		if (!strcmp("L16", rtp_end->subtype_name))
			return AF_L16;
	}

	switch (rtp_end->payload_type) {
	case 3 /* GSM */:
		return AF_GSM;
	case 8 /* PCMA */:
		return AF_PCMA;
#ifdef HAVE_BCG729
	case 18 /* G.729 */:
		return AF_G729;
#endif
	case 11 /* L16 */:
		return AF_L16;
	default:
		return AF_INVALID;
	}
}

static void l16_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n, ++sample, buf += 2) {
		buf[0] = sample[0] >> 8;
		buf[1] = sample[0] & 0xff;
	}
}

static void l16_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n, ++sample, buf += 2)
		sample[0] = ((short)buf[0] << 8) | buf[1];
}

static void alaw_encode(short *sample, unsigned char *buf, size_t n)
{
	for (; n > 0; --n)
		*(buf++) = s16_to_alaw(*(sample++));
}

static void alaw_decode(unsigned char *buf, short *sample, size_t n)
{
	for (; n > 0; --n)
		*(sample++) = alaw_to_s16(*(buf++));
}

static int processing_state_destructor(struct mgcp_process_rtp_state *state)
{
	switch (state->src_fmt) {
	case AF_GSM:
		if (state->dst.gsm_handle)
			gsm_destroy(state->src.gsm_handle);
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		if (state->src.g729_dec)
			closeBcg729DecoderChannel(state->src.g729_dec);
		break;
#endif
	default:
		break;
	}
	switch (state->dst_fmt) {
	case AF_GSM:
		if (state->dst.gsm_handle)
			gsm_destroy(state->dst.gsm_handle);
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		if (state->dst.g729_enc)
			closeBcg729EncoderChannel(state->dst.g729_enc);
		break;
#endif
	default:
		break;
	}
	return 0;
}

int mgcp_setup_processing(struct mgcp_endpoint *endp,
			  struct mgcp_rtp_end *dst_end,
			  struct mgcp_rtp_end *src_end)
{
	struct mgcp_process_rtp_state *state = dst_end->rtp_process_data;
	enum audio_format src_fmt, dst_fmt;

	/* cleanup first */
	if (state) {
		talloc_free(state);
		dst_end->rtp_process_data = NULL;
	}

	if (!src_end)
		return 0;

	src_fmt = get_audio_format(src_end);
	dst_fmt = get_audio_format(dst_end);

	if (!src_fmt || !dst_fmt) {
		if (src_end->payload_type == dst_end->payload_type)
			/* Nothing to do */
			return 0;

		LOGP(DMGCP, LOGL_ERROR, "Cannot transcode: %s codec not supported.\n",
		     src_fmt ? "destination" : "source");
		return -EINVAL;
	}

	if (src_end->rate && dst_end->rate && src_end->rate != dst_end->rate) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot transcode: rate conversion (%d -> %d) not supported.\n",
		     src_end->rate, dst_end->rate);
		return -EINVAL;
	}

	state = talloc_zero(NULL, struct mgcp_process_rtp_state);
	talloc_set_destructor(state, processing_state_destructor);
	dst_end->rtp_process_data = state;

	state->src_fmt = src_fmt;

	switch (state->src_fmt) {
	case AF_L16:
	case AF_S16:
		state->src_frame_size = 80 * sizeof(short);
		state->src_samples_per_frame = 80;
		break;
	case AF_GSM:
		state->src_frame_size = sizeof(gsm_frame);
		state->src_samples_per_frame = 160;
		state->src.gsm_handle = gsm_create();
		if (!state->src.gsm_handle) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize GSM decoder.\n");
			return -EINVAL;
		}
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		state->src_frame_size = 10;
		state->src_samples_per_frame = 80;
		state->src.g729_dec = initBcg729DecoderChannel();
		if (!state->src.g729_dec) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize G.729 decoder.\n");
			return -EINVAL;
		}
		break;
#endif
	case AF_PCMA:
		state->src_frame_size = 80;
		state->src_samples_per_frame = 80;
		break;
	default:
		break;
	}

	state->dst_fmt = dst_fmt;

	switch (state->dst_fmt) {
	case AF_L16:
	case AF_S16:
		state->dst_frame_size = 80*sizeof(short);
		state->dst_samples_per_frame = 80;
		break;
	case AF_GSM:
		state->dst_frame_size = sizeof(gsm_frame);
		state->dst_samples_per_frame = 160;
		state->dst.gsm_handle = gsm_create();
		if (!state->dst.gsm_handle) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize GSM encoder.\n");
			return -EINVAL;
		}
		break;
#ifdef HAVE_BCG729
	case AF_G729:
		state->dst_frame_size = 10;
		state->dst_samples_per_frame = 80;
		state->dst.g729_enc = initBcg729EncoderChannel();
		if (!state->dst.g729_enc) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize G.729 decoder.\n");
			return -EINVAL;
		}
		break;
#endif
	case AF_PCMA:
		state->dst_frame_size = 80;
		state->dst_samples_per_frame = 80;
		break;
	default:
		break;
	}

	LOGP(DMGCP, LOGL_INFO,
	     "Initialized RTP processing on: 0x%x "
	     "conv: %d (%d, %d, %s) -> %d (%d, %d, %s)\n",
	     ENDPOINT_NUMBER(endp),
	     src_fmt, src_end->payload_type, src_end->rate, src_end->fmtp_extra,
	     dst_fmt, dst_end->payload_type, dst_end->rate, dst_end->fmtp_extra);

	return 0;
}

void mgcp_net_downlink_format(struct mgcp_endpoint *endp,
			      int *payload_type,
			      const char**audio_name,
			      const char**fmtp_extra)
{
	struct mgcp_process_rtp_state *state = endp->net_end.rtp_process_data;
	if (!state || endp->net_end.payload_type < 0) {
		*payload_type = endp->bts_end.payload_type;
		*audio_name = endp->bts_end.audio_name;
		*fmtp_extra = endp->bts_end.fmtp_extra;
		return;
	}

	*payload_type = endp->net_end.payload_type;
	*fmtp_extra = endp->net_end.fmtp_extra;
	*audio_name = endp->net_end.audio_name;
}


int mgcp_process_rtp_payload(struct mgcp_endpoint *endp,
				struct mgcp_rtp_end *dst_end,
			     char *data, int *len, int buf_size)
{
	struct mgcp_process_rtp_state *state = dst_end->rtp_process_data;
	size_t rtp_hdr_size = 12;
	char *payload_data = data + rtp_hdr_size;
	int payload_len = *len - rtp_hdr_size;
	size_t sample_idx;
	uint8_t *src = (uint8_t *)payload_data;
	uint8_t *dst = (uint8_t *)payload_data;
	size_t nbytes = payload_len;
	size_t frame_remainder;
	uint32_t ts_no;

	if (!state)
		return 0;

	if (state->src_fmt == state->dst_fmt)
		return 0;

	/* TODO: check payload type (-> G.711 comfort noise) */

	/* Decode src into samples */
	while (nbytes >= state->src_frame_size) {
		if (state->sample_cnt + state->src_samples_per_frame > ARRAY_SIZE(state->samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small: %d > %d.\n",
			     state->sample_cnt + state->src_samples_per_frame,
			     ARRAY_SIZE(state->samples));
			return -ENOSPC;
		}
		switch (state->src_fmt) {
		case AF_GSM:
			if (gsm_decode(state->src.gsm_handle,
				       (gsm_byte *)src, state->samples + state->sample_cnt) < 0) {
				LOGP(DMGCP, LOGL_ERROR,
				     "Failed to decode GSM.\n");
				return -EINVAL;
			}
			break;
#ifdef HAVE_BCG729
		case AF_G729:
			bcg729Decoder(state->src.g729_dec, src, 0, state->samples + state->sample_cnt);
			break;
#endif
		case AF_PCMA:
			alaw_decode(src, state->samples + state->sample_cnt,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(state->samples + state->sample_cnt, src,
				state->src_frame_size);
			break;
		case AF_L16:
			l16_decode(src, state->samples + state->sample_cnt,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		src        += state->src_frame_size;
		nbytes     -= state->src_frame_size;
		state->sample_cnt += state->src_samples_per_frame;
	}

	/* Add silence if necessary */
	/* sigh...this equipment doesn't honor the ptime... */
	frame_remainder = state->sample_cnt % state->dst_samples_per_frame;
	if (frame_remainder) {
#if 0
		size_t silence = state->dst_samples_per_frame - frame_remainder;
		printf("Adding silence: %zu\n", silence);
		if (sample_cnt + silence > ARRAY_SIZE(samples)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Sample buffer too small for silence: %d > %d.\n",
			     sample_cnt + silence,
			     ARRAY_SIZE(samples));
			return -ENOSPC;
		}

		while (silence > 0) {
			samples[sample_cnt] = 0;
			sample_cnt += 1;
			silence -= 1;
		}
#else
		size_t samples = state->dst_samples_per_frame - frame_remainder;
		LOGP(DMGCP, LOGL_NOTICE, "Waiting for... %zu\n", samples);

		/* remember... */
		if (!state->second_packet) {
			memcpy(&state->next_seq, &data[2], 2);
			state->ptime_different = 1;
		}
		state->second_packet = 1;

		return -1;
#endif
	}

	/* G729 sends us ptime=40 */
	if (state->sample_cnt == 2 * state->dst_samples_per_frame) {
		if (!state->second_packet) {
			printf("TOO MUCH data in one packet?\n");
			memcpy(&state->next_seq, &data[2], 2);
			state->ptime_different = 1;
		}
	}

	state->second_packet = 1;
	memcpy(&ts_no, &data[4], 4);

	/* Encode samples into dst */
	sample_idx = 0;
	nbytes = 0;
	while (sample_idx + state->dst_samples_per_frame <= state->sample_cnt) {
		if (nbytes + state->dst_frame_size > buf_size) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Encoding (RTP) buffer too small: %d > %d.\n",
			     nbytes + state->dst_frame_size, buf_size);
			return -ENOSPC;
		}
		switch (state->dst_fmt) {
		case AF_GSM:
			gsm_encode(state->dst.gsm_handle,
				   state->samples + sample_idx, dst);
			break;
#ifdef HAVE_BCG729
		case AF_G729:
			bcg729Encoder(state->dst.g729_enc,
				      state->samples + sample_idx, dst);
			break;
#endif
		case AF_PCMA:
			alaw_encode(state->samples + sample_idx, dst,
				    state->src_samples_per_frame);
			break;
		case AF_S16:
			memmove(dst, state->samples + sample_idx, state->dst_frame_size);
			break;
		case AF_L16:
			l16_encode(state->samples + sample_idx, dst,
				   state->src_samples_per_frame);
			break;
		default:
			break;
		}
		//dst        += state->dst_frame_size;
		nbytes     += state->dst_frame_size;
		sample_idx += state->dst_samples_per_frame;

		*len = rtp_hdr_size + state->dst_frame_size;
		/* Patch payload type */
		data[1] = (data[1] & 0x80) | (dst_end->payload_type & 0x7f);
		if (state->ptime_different) {
			memcpy(&data[2], &state->next_seq, 2);
			memcpy(&data[4], &ts_no, 4);
			state->next_seq = htons(ntohs(state->next_seq) + 1);
			ts_no = htonl(ntohl(ts_no) + state->dst_samples_per_frame);
		}
		mgcp_do_send(endp, dst_end, (char *)dst, *len);
	}

	state->sample_cnt = 0;

	/* TODO: remove me
	fprintf(stderr, "sample_cnt = %d, sample_idx = %d, plen = %d -> %d, "
		"hdr_size = %d, len = %d, pt = %d\n",
	       sample_cnt, sample_idx, payload_len, nbytes, rtp_hdr_size, *len,
	       data[1]);
	       */

	return -1;
}
