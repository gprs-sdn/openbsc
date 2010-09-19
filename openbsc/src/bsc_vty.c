/* OpenBSC interface to quagga VTY */
/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

#include <arpa/inet.h>

#include <osmocore/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>
#include <osmocore/utils.h>
#include <osmocore/gsm_utils.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/meas_rep.h>
#include <openbsc/db.h>
#include <osmocore/talloc.h>
#include <openbsc/vty.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/system_information.h>
#include <openbsc/debug.h>

#include "../bscconfig.h"

/* FIXME: this should go to some common file */
static const struct value_string gprs_ns_timer_strs[] = {
	{ 0, "tns-block" },
	{ 1, "tns-block-retries" },
	{ 2, "tns-reset" },
	{ 3, "tns-reset-retries" },
	{ 4, "tns-test" },
	{ 5, "tns-alive" },
	{ 6, "tns-alive-retries" },
	{ 0, NULL }
};

static const struct value_string gprs_bssgp_cfg_strs[] = {
	{ 0,	"blocking-timer" },
	{ 1,	"blocking-retries" },
	{ 2,	"unblocking-retries" },
	{ 3,	"reset-timer" },
	{ 4,	"reset-retries" },
	{ 5,	"suspend-timer" },
	{ 6,	"suspend-retries" },
	{ 7,	"resume-timer" },
	{ 8,	"resume-retries" },
	{ 9,	"capability-update-timer" },
	{ 10,	"capability-update-retries" },
	{ 0,	NULL }
};

struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(network)#",
	1,
};

struct cmd_node bts_node = {
	BTS_NODE,
	"%s(bts)#",
	1,
};

struct cmd_node trx_node = {
	TRX_NODE,
	"%s(trx)#",
	1,
};

struct cmd_node ts_node = {
	TS_NODE,
	"%s(ts)#",
	1,
};

extern struct gsm_network *bsc_gsmnet;

struct gsm_network *gsmnet_from_vty(struct vty *v)
{
	/* In case we read from the config file, the vty->priv cannot
	 * point to a struct telnet_connection, and thus conn->priv
	 * will not point to the gsm_network structure */
#if 0
	struct telnet_connection *conn = v->priv;
	return (struct gsm_network *) conn->priv;
#else
	return bsc_gsmnet;
#endif
}

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

static void net_dump_nmstate(struct vty *vty, struct gsm_nm_state *nms)
{
	vty_out(vty,"Oper '%s', Admin %u, Avail '%s'%s",
		nm_opstate_name(nms->operational), nms->administrative,
		nm_avail_name(nms->availability), VTY_NEWLINE);
}

static void dump_pchan_load_vty(struct vty *vty, char *prefix,
				const struct pchan_load *pl)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pl->pchan); i++) {
		const struct load_counter *lc = &pl->pchan[i];
		unsigned int percent;

		if (lc->total == 0)
			continue;

		percent = (lc->used * 100) / lc->total;

		vty_out(vty, "%s%20s: %3u%% (%u/%u)%s", prefix,
			gsm_pchan_name(i), percent, lc->used, lc->total,
			VTY_NEWLINE);
	}
}

static void net_dump_vty(struct vty *vty, struct gsm_network *net)
{
	struct pchan_load pl;

	vty_out(vty, "BSC is on Country Code %u, Network Code %u "
		"and has %u BTS%s", net->country_code, net->network_code,
		net->num_bts, VTY_NEWLINE);
	vty_out(vty, "  Long network name: '%s'%s",
		net->name_long, VTY_NEWLINE);
	vty_out(vty, "  Short network name: '%s'%s",
		net->name_short, VTY_NEWLINE);
	vty_out(vty, "  Authentication policy: %s%s",
		gsm_auth_policy_name(net->auth_policy), VTY_NEWLINE);
	vty_out(vty, "  Location updating reject cause: %u%s",
		net->reject_cause, VTY_NEWLINE);
	vty_out(vty, "  Encryption: A5/%u%s", net->a5_encryption,
		VTY_NEWLINE);
	vty_out(vty, "  NECI (TCH/H): %u%s", net->neci,
		VTY_NEWLINE);
	vty_out(vty, "  Use TCH for Paging any: %d%s", net->pag_any_tch,
		VTY_NEWLINE);
	vty_out(vty, "  RRLP Mode: %s%s", rrlp_mode_name(net->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, "  MM Info: %s%s", net->send_mm_info ? "On" : "Off",
		VTY_NEWLINE);
	vty_out(vty, "  Handover: %s%s", net->handover.active ? "On" : "Off",
		VTY_NEWLINE);
	network_chan_load(&pl, net);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);
}

DEFUN(show_net, show_net_cmd, "show network",
	SHOW_STR "Display information about a GSM NETWORK\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net_dump_vty(vty, net);

	return CMD_SUCCESS;
}

static void e1isl_dump_vty(struct vty *vty, struct e1inp_sign_link *e1l)
{
	struct e1inp_line *line;

	if (!e1l) {
		vty_out(vty, "   None%s", VTY_NEWLINE);
		return;
	}

	line = e1l->ts->line;

	vty_out(vty, "    E1 Line %u, Type %s: Timeslot %u, Mode %s%s",
		line->num, line->driver->name, e1l->ts->num,
		e1inp_signtype_name(e1l->type), VTY_NEWLINE);
	vty_out(vty, "    E1 TEI %u, SAPI %u%s",
		e1l->tei, e1l->sapi, VTY_NEWLINE);
}

static void bts_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct pchan_load pl;

	vty_out(vty, "BTS %u is of %s type in band %s, has CI %u LAC %u, "
		"BSIC %u, TSC %u and %u TRX%s",
		bts->nr, btstype2str(bts->type), gsm_band_name(bts->band),
		bts->cell_identity,
		bts->location_area_code, bts->bsic, bts->tsc,
		bts->num_trx, VTY_NEWLINE);
	vty_out(vty, "Description: %s%s",
		bts->description ? bts->description : "(null)", VTY_NEWLINE);
	vty_out(vty, "MS Max power: %u dBm%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "Minimum Rx Level for Access: %i dBm%s",
		rxlev2dbm(bts->si_common.cell_sel_par.rxlev_acc_min),
		VTY_NEWLINE);
	vty_out(vty, "Cell Reselection Hysteresis: %u dBm%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "RACH TX-Integer: %u%s", bts->si_common.rach_control.tx_integer,
		VTY_NEWLINE);
	vty_out(vty, "RACH Max transmissions: %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  CELL IS BARRED%s", VTY_NEWLINE);
	vty_out(vty, "System Information present: 0x%08x, static: 0x%08x%s",
		bts->si_valid, bts->si_mode_static, VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  Unit ID: %u/%u/0, OML Stream ID 0x%02x%s",
			bts->ip_access.site_id, bts->ip_access.bts_id,
			bts->oml_tei, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &bts->nm_state);
	vty_out(vty, "  Site Mgr NM State: ");
	net_dump_nmstate(vty, &bts->site_mgr.nm_state);
	vty_out(vty, "  Paging: FIXME pending requests, %u free slots%s",
		bts->paging.available_slots, VTY_NEWLINE);
	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, bts->oml_link);
	}
	/* FIXME: oml_link, chan_desc */
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);
}

DEFUN(show_bts, show_bts_cmd, "show bts [number]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr;

	if (argc != 0) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr > net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));
		return CMD_SUCCESS;
	}
	/* print all BTS's */
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));

	return CMD_SUCCESS;
}

/* utility functions */
static void parse_e1_link(struct gsm_e1_subslot *e1_link, const char *line,
			  const char *ts, const char *ss)
{
	e1_link->e1_nr = atoi(line);
	e1_link->e1_ts = atoi(ts);
	if (!strcmp(ss, "full"))
		e1_link->e1_ts_ss = 255;
	else
		e1_link->e1_ts_ss = atoi(ss);
}

static void config_write_e1_link(struct vty *vty, struct gsm_e1_subslot *e1_link,
				 const char *prefix)
{
	if (!e1_link->e1_ts)
		return;

	if (e1_link->e1_ts_ss == 255)
		vty_out(vty, "%se1 line %u timeslot %u sub-slot full%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts, VTY_NEWLINE);
	else
		vty_out(vty, "%se1 line %u timeslot %u sub-slot %u%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts,
			e1_link->e1_ts_ss, VTY_NEWLINE);
}


static void config_write_ts_single(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "    timeslot %u%s", ts->nr, VTY_NEWLINE);
	if (ts->pchan != GSM_PCHAN_NONE)
		vty_out(vty, "     phys_chan_config %s%s",
			gsm_pchan_name(ts->pchan), VTY_NEWLINE);
	vty_out(vty, "     hopping enabled %u%s",
		ts->hopping.enabled, VTY_NEWLINE);
	if (ts->hopping.enabled) {
		unsigned int i;
		vty_out(vty, "     hopping sequence-number %u%s",
			ts->hopping.hsn, VTY_NEWLINE);
		vty_out(vty, "     hopping maio %u%s",
			ts->hopping.maio, VTY_NEWLINE);
		for (i = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (!bitvec_get_bit_pos(&ts->hopping.arfcns, i))
				continue;
			vty_out(vty, "     hopping arfcn add %u%s",
				i, VTY_NEWLINE);
		}
	} else
	config_write_e1_link(vty, &ts->e1_link, "     ");
}

static void config_write_trx_single(struct vty *vty, struct gsm_bts_trx *trx)
{
	int i;

	vty_out(vty, "  trx %u%s", trx->nr, VTY_NEWLINE);
	if (trx->description)
		vty_out(vty, "   description %s%s", trx->description,
			VTY_NEWLINE);
	vty_out(vty, "   rf_locked %u%s",
		trx->nm_state.administrative == NM_STATE_LOCKED ? 1 : 0,
		VTY_NEWLINE);
	vty_out(vty, "   arfcn %u%s", trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "   nominal power %u%s", trx->nominal_power, VTY_NEWLINE);
	vty_out(vty, "   max_power_red %u%s", trx->max_power_red, VTY_NEWLINE);
	config_write_e1_link(vty, &trx->rsl_e1_link, "   rsl ");
	vty_out(vty, "   rsl e1 tei %u%s", trx->rsl_tei, VTY_NEWLINE);

	for (i = 0; i < TRX_NR_TS; i++)
		config_write_ts_single(vty, &trx->ts[i]);
}

static void config_write_bts_gprs(struct vty *vty, struct gsm_bts *bts)
{
	unsigned int i;
	vty_out(vty, "  gprs mode %s%s", bts_gprs_mode_name(bts->gprs.mode),
		VTY_NEWLINE);
	if (bts->gprs.mode == BTS_GPRS_NONE)
		return;

	vty_out(vty, "  gprs routing area %u%s", bts->gprs.rac,
		VTY_NEWLINE);
	vty_out(vty, "  gprs cell bvci %u%s", bts->gprs.cell.bvci,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.cell.timer); i++)
		vty_out(vty, "  gprs cell timer %s %u%s",
			get_value_string(gprs_bssgp_cfg_strs, i),
			bts->gprs.cell.timer[i], VTY_NEWLINE);
	vty_out(vty, "  gprs nsei %u%s", bts->gprs.nse.nsei,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.nse.timer); i++)
		vty_out(vty, "  gprs ns timer %s %u%s",
			get_value_string(gprs_ns_timer_strs, i),
			bts->gprs.nse.timer[i], VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.nsvc); i++) {
		struct gsm_bts_gprs_nsvc *nsvc =
					&bts->gprs.nsvc[i];
		struct in_addr ia;

		ia.s_addr = htonl(nsvc->remote_ip);
		vty_out(vty, "  gprs nsvc %u nsvci %u%s", i,
			nsvc->nsvci, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u local udp port %u%s", i,
			nsvc->local_port, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u remote udp port %u%s", i,
			nsvc->remote_port, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u remote ip %s%s", i,
			inet_ntoa(ia), VTY_NEWLINE);
	}
}

static void config_write_bts_single(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	int i;

	vty_out(vty, " bts %u%s", bts->nr, VTY_NEWLINE);
	vty_out(vty, "  type %s%s", btstype2str(bts->type), VTY_NEWLINE);
	if (bts->description)
		vty_out(vty, "  description %s%s", bts->description, VTY_NEWLINE);
	vty_out(vty, "  band %s%s", gsm_band_name(bts->band), VTY_NEWLINE);
	vty_out(vty, "  cell_identity %u%s", bts->cell_identity, VTY_NEWLINE);
	vty_out(vty, "  location_area_code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	vty_out(vty, "  training_sequence_code %u%s", bts->tsc, VTY_NEWLINE);
	vty_out(vty, "  base_station_id_code %u%s", bts->bsic, VTY_NEWLINE);
	vty_out(vty, "  ms max power %u%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "  cell reselection hysteresis %u%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "  rxlev access min %u%s",
		bts->si_common.cell_sel_par.rxlev_acc_min, VTY_NEWLINE);
	if (bts->si_common.chan_desc.t3212)
		vty_out(vty, "  periodic location update %u%s",
			bts->si_common.chan_desc.t3212 * 10, VTY_NEWLINE);
	vty_out(vty, "  channel allocator %s%s",
		bts->chan_alloc_reverse ? "descending" : "ascending",
		VTY_NEWLINE);
	vty_out(vty, "  rach tx integer %u%s",
		bts->si_common.rach_control.tx_integer, VTY_NEWLINE);
	vty_out(vty, "  rach max transmission %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);

	if (bts->rach_b_thresh != -1)
		vty_out(vty, "  rach nm busy threshold %u%s",
			bts->rach_b_thresh, VTY_NEWLINE);
	if (bts->rach_ldavg_slots != -1)
		vty_out(vty, "  rach nm load average %u%s",
			bts->rach_ldavg_slots, VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  cell barred 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0x4) == 0)
		vty_out(vty, "  rach emergency call allowed 1%s", VTY_NEWLINE);
	for (i = SYSINFO_TYPE_1; i < _MAX_SYSINFO_TYPE; i++) {
		if (bts->si_mode_static & (1 << i)) {
			vty_out(vty, "  system-information %s mode static%s",
				get_value_string(osmo_sitype_strs, i), VTY_NEWLINE);
			vty_out(vty, "  system-information %s static %s%s",
				get_value_string(osmo_sitype_strs, i),
				hexdump_nospc(bts->si_buf[i], sizeof(bts->si_buf[i])),
				VTY_NEWLINE);
		}
	}
	if (is_ipaccess_bts(bts)) {
		vty_out(vty, "  ip.access unit_id %u %u%s",
			bts->ip_access.site_id, bts->ip_access.bts_id, VTY_NEWLINE);
		vty_out(vty, "  oml ip.access stream_id %u%s", bts->oml_tei, VTY_NEWLINE);
	} else {
		config_write_e1_link(vty, &bts->oml_e1_link, "  oml ");
		vty_out(vty, "  oml e1 tei %u%s", bts->oml_tei, VTY_NEWLINE);
	}

	/* if we have a limit, write it */
	if (bts->paging.free_chans_need >= 0)
		vty_out(vty, "  paging free %d%s", bts->paging.free_chans_need, VTY_NEWLINE);

	config_write_bts_gprs(vty, bts);

	llist_for_each_entry(trx, &bts->trx_list, list)
		config_write_trx_single(vty, trx);
}

static int config_write_bts(struct vty *v)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(v);
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &gsmnet->bts_list, list)
		config_write_bts_single(v, bts);

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "network%s", VTY_NEWLINE);
	vty_out(vty, " network country code %u%s", gsmnet->country_code, VTY_NEWLINE);
	vty_out(vty, " mobile network code %u%s", gsmnet->network_code, VTY_NEWLINE);
	vty_out(vty, " short name %s%s", gsmnet->name_short, VTY_NEWLINE);
	vty_out(vty, " long name %s%s", gsmnet->name_long, VTY_NEWLINE);
	vty_out(vty, " auth policy %s%s", gsm_auth_policy_name(gsmnet->auth_policy), VTY_NEWLINE);
	vty_out(vty, " location updating reject cause %u%s",
		gsmnet->reject_cause, VTY_NEWLINE);
	vty_out(vty, " encryption a5 %u%s", gsmnet->a5_encryption, VTY_NEWLINE);
	vty_out(vty, " neci %u%s", gsmnet->neci, VTY_NEWLINE);
	vty_out(vty, " paging any use tch %d%s", gsmnet->pag_any_tch, VTY_NEWLINE);
	vty_out(vty, " rrlp mode %s%s", rrlp_mode_name(gsmnet->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, " mm info %u%s", gsmnet->send_mm_info, VTY_NEWLINE);
	vty_out(vty, " handover %u%s", gsmnet->handover.active, VTY_NEWLINE);
	vty_out(vty, " handover window rxlev averaging %u%s",
		gsmnet->handover.win_rxlev_avg, VTY_NEWLINE);
	vty_out(vty, " handover window rxqual averaging %u%s",
		gsmnet->handover.win_rxqual_avg, VTY_NEWLINE);
	vty_out(vty, " handover window rxlev neighbor averaging %u%s",
		gsmnet->handover.win_rxlev_avg_neigh, VTY_NEWLINE);
	vty_out(vty, " handover power budget interval %u%s",
		gsmnet->handover.pwr_interval, VTY_NEWLINE);
	vty_out(vty, " handover power budget hysteresis %u%s",
		gsmnet->handover.pwr_hysteresis, VTY_NEWLINE);
	vty_out(vty, " handover maximum distance %u%s",
		gsmnet->handover.max_distance, VTY_NEWLINE);
	vty_out(vty, " timer t3101 %u%s", gsmnet->T3101, VTY_NEWLINE);
	vty_out(vty, " timer t3103 %u%s", gsmnet->T3103, VTY_NEWLINE);
	vty_out(vty, " timer t3105 %u%s", gsmnet->T3105, VTY_NEWLINE);
	vty_out(vty, " timer t3107 %u%s", gsmnet->T3107, VTY_NEWLINE);
	vty_out(vty, " timer t3109 %u%s", gsmnet->T3109, VTY_NEWLINE);
	vty_out(vty, " timer t3111 %u%s", gsmnet->T3111, VTY_NEWLINE);
	vty_out(vty, " timer t3113 %u%s", gsmnet->T3113, VTY_NEWLINE);
	vty_out(vty, " timer t3115 %u%s", gsmnet->T3115, VTY_NEWLINE);
	vty_out(vty, " timer t3117 %u%s", gsmnet->T3117, VTY_NEWLINE);
	vty_out(vty, " timer t3119 %u%s", gsmnet->T3119, VTY_NEWLINE);
	vty_out(vty, " timer t3141 %u%s", gsmnet->T3141, VTY_NEWLINE);
	vty_out(vty, " use-dtx %u%s", gsmnet->dtx_enabled, VTY_NEWLINE);

	return CMD_SUCCESS;
}

static void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx)
{
	vty_out(vty, "TRX %u of BTS %u is on ARFCN %u%s",
		trx->nr, trx->bts->nr, trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "Description: %s%s",
		trx->description ? trx->description : "(null)", VTY_NEWLINE);
	vty_out(vty, "  RF Nominal Power: %d dBm, reduced by %u dB, "
		"resulting BS power: %d dBm%s",
		trx->nominal_power, trx->max_power_red,
		trx->nominal_power - trx->max_power_red, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &trx->nm_state);
	vty_out(vty, "  Baseband Transceiver NM State: ");
	net_dump_nmstate(vty, &trx->bb_transc.nm_state);
	if (is_ipaccess_bts(trx->bts)) {
		vty_out(vty, "  ip.access stream ID: 0x%02x%s",
			trx->rsl_tei, VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, trx->rsl_link);
	}
}

DEFUN(show_trx,
      show_trx_cmd,
      "show trx [bts_nr] [trx_nr]",
	SHOW_STR "Display information about a TRX\n"
	"BTS Number\n"
	"TRX Number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx;
	int bts_nr, trx_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
		trx_dump_vty(vty, trx);
		return CMD_SUCCESS;
	}
	if (bts) {
		/* print all TRX in this BTS */
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			trx_dump_vty(vty, trx);
		}
		return CMD_SUCCESS;
	}

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			trx_dump_vty(vty, trx);
		}
	}

	return CMD_SUCCESS;
}


static void ts_dump_vty(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "Timeslot %u of TRX %u in BTS %u, phys cfg %s%s",
		ts->nr, ts->trx->nr, ts->trx->bts->nr,
		gsm_pchan_name(ts->pchan), VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &ts->nm_state);
	if (!is_ipaccess_bts(ts->trx->bts))
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
}

DEFUN(show_ts,
      show_ts_cmd,
      "show timeslot [bts_nr] [trx_nr] [ts_nr]",
	SHOW_STR "Display information about a TS\n"
	"BTS Number\n" "TRX Number\n" "Timeslot Number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	int bts_nr, trx_nr, ts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS '%s'%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];
		ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
				ts = &trx->ts[ts_nr];
				ts_dump_vty(vty, ts);
			}
		}
	}

	return CMD_SUCCESS;
}

static void subscr_dump_vty(struct vty *vty, struct gsm_subscriber *subscr)
{
	vty_out(vty, "    ID: %llu, Authorized: %d%s", subscr->id,
		subscr->authorized, VTY_NEWLINE);
	if (subscr->name)
		vty_out(vty, "    Name: '%s'%s", subscr->name, VTY_NEWLINE);
	if (subscr->extension)
		vty_out(vty, "    Extension: %s%s", subscr->extension,
			VTY_NEWLINE);
	if (subscr->imsi)
		vty_out(vty, "    IMSI: %s%s", subscr->imsi, VTY_NEWLINE);
	if (subscr->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", subscr->tmsi,
			VTY_NEWLINE);

	vty_out(vty, "    Use count: %u%s", subscr->use_count, VTY_NEWLINE);
}

static void meas_rep_dump_uni_vty(struct vty *vty,
				  struct gsm_meas_rep_unidir *mru,
				  const char *prefix,
				  const char *dir)
{
	vty_out(vty, "%s  RXL-FULL-%s: %4d dBm, RXL-SUB-%s: %4d dBm ",
		prefix, dir, rxlev2dbm(mru->full.rx_lev),
			dir, rxlev2dbm(mru->sub.rx_lev));
	vty_out(vty, "RXQ-FULL-%s: %d, RXQ-SUB-%s: %d%s",
		dir, mru->full.rx_qual, dir, mru->sub.rx_qual,
		VTY_NEWLINE);
}

static void meas_rep_dump_vty(struct vty *vty, struct gsm_meas_rep *mr,
			      const char *prefix)
{
	vty_out(vty, "%sMeasurement Report:%s", prefix, VTY_NEWLINE);
	vty_out(vty, "%s  Flags: %s%s%s%s%s", prefix,
			mr->flags & MEAS_REP_F_UL_DTX ? "DTXu " : "",
			mr->flags & MEAS_REP_F_DL_DTX ? "DTXd " : "",
			mr->flags & MEAS_REP_F_FPC ? "FPC " : "",
			mr->flags & MEAS_REP_F_DL_VALID ? " " : "DLinval ",
			VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_TO)
		vty_out(vty, "%s  MS Timing Offset: %u%s", prefix,
			mr->ms_timing_offset, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_L1)
		vty_out(vty, "%s  L1 MS Power: %u dBm, Timing Advance: %u%s",
			prefix, mr->ms_l1.pwr, mr->ms_l1.ta, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_DL_VALID)
		meas_rep_dump_uni_vty(vty, &mr->dl, prefix, "dl");
	meas_rep_dump_uni_vty(vty, &mr->ul, prefix, "ul");
}

static void lchan_dump_full_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	int idx;

	vty_out(vty, "Lchan %u in Timeslot %u of TRX %u in BTS %u, Type %s%s",
		lchan->nr, lchan->ts->nr, lchan->ts->trx->nr,
		lchan->ts->trx->bts->nr, gsm_lchant_name(lchan->type),
		VTY_NEWLINE);
	vty_out(vty, "  Connection: %u, State: %s%s",
		lchan->conn ? 1: 0,
		gsm_lchans_name(lchan->state), VTY_NEWLINE);
	vty_out(vty, "  BS Power: %u dBm, MS Power: %u dBm%s",
		lchan->ts->trx->nominal_power - lchan->ts->trx->max_power_red
		- lchan->bs_power*2,
		ms_pwr_dbm(lchan->ts->trx->bts->band, lchan->ms_power),
		VTY_NEWLINE);
	if (lchan->conn && lchan->conn->subscr) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_vty(vty, lchan->conn->subscr);
	} else
		vty_out(vty, "  No Subscriber%s", VTY_NEWLINE);
	if (is_ipaccess_bts(lchan->ts->trx->bts)) {
		struct in_addr ia;
		ia.s_addr = htonl(lchan->abis_ip.bound_ip);
		vty_out(vty, "  Bound IP: %s Port %u RTP_TYPE2=%u CONN_ID=%u%s",
			inet_ntoa(ia), lchan->abis_ip.bound_port,
			lchan->abis_ip.rtp_payload2, lchan->abis_ip.conn_id,
			VTY_NEWLINE);
	}

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	meas_rep_dump_vty(vty, &lchan->meas_rep[idx], "  ");
}

static void lchan_dump_short_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	struct gsm_meas_rep *mr;
	int idx;

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	mr =  &lchan->meas_rep[idx];

	vty_out(vty, "Lchan: %u Timeslot: %u TRX: %u BTS: %u Type: %s - L1 MS Power: %u dBm "
		     "RXL-FULL-dl: %4d dBm RXL-FULL-ul: %4d dBm%s",
		lchan->nr, lchan->ts->nr, lchan->ts->trx->nr,
		lchan->ts->trx->bts->nr, gsm_lchant_name(lchan->type),
		mr->ms_l1.pwr,
		rxlev2dbm(mr->dl.full.rx_lev),
		rxlev2dbm(mr->ul.full.rx_lev),
		VTY_NEWLINE);
}

static int lchan_summary(struct vty *vty, int argc, const char **argv,
			 void (*dump_cb)(struct vty *, struct gsm_lchan *))
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int bts_nr, trx_nr, ts_nr, lchan_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS %s%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];
	}
	if (argc >= 4) {
		lchan_nr = atoi(argv[3]);
		if (lchan_nr >= TS_MAX_LCHAN) {
			vty_out(vty, "%% can't find LCHAN %s%s", argv[3],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		lchan = &ts->lchan[lchan_nr];
		dump_cb(vty, lchan);
		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
				ts = &trx->ts[ts_nr];
				for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN;
				     lchan_nr++) {
					lchan = &ts->lchan[lchan_nr];
					if (lchan->type == GSM_LCHAN_NONE)
						continue;
					dump_cb(vty, lchan);
				}
			}
		}
	}

	return CMD_SUCCESS;
}


DEFUN(show_lchan,
      show_lchan_cmd,
      "show lchan [bts_nr] [trx_nr] [ts_nr] [lchan_nr]",
	SHOW_STR "Display information about a logical channel\n"
	"BTS Number\n" "TRX Number\n" "Timeslot Number\n"
	"Logical Channel Number\n")

{
	return lchan_summary(vty, argc, argv, lchan_dump_full_vty);
}

DEFUN(show_lchan_summary,
      show_lchan_summary_cmd,
      "show lchan summary [bts_nr] [trx_nr] [ts_nr] [lchan_nr]",
	SHOW_STR "Display information about a logical channel\n"
	"BTS Number\n" "TRX Number\n" "Timeslot Number\n"
	"Logical Channel Number\n")
{
	return lchan_summary(vty, argc, argv, lchan_dump_short_vty);
}

static void e1drv_dump_vty(struct vty *vty, struct e1inp_driver *drv)
{
	vty_out(vty, "E1 Input Driver %s%s", drv->name, VTY_NEWLINE);
}

DEFUN(show_e1drv,
      show_e1drv_cmd,
      "show e1_driver",
	SHOW_STR "Display information about available E1 drivers\n")
{
	struct e1inp_driver *drv;

	llist_for_each_entry(drv, &e1inp_driver_list, list)
		e1drv_dump_vty(vty, drv);

	return CMD_SUCCESS;
}

static void e1line_dump_vty(struct vty *vty, struct e1inp_line *line)
{
	vty_out(vty, "E1 Line Number %u, Name %s, Driver %s%s",
		line->num, line->name ? line->name : "",
		line->driver->name, VTY_NEWLINE);
}

DEFUN(show_e1line,
      show_e1line_cmd,
      "show e1_line [line_nr]",
	SHOW_STR "Display information about a E1 line\n"
	"E1 Line Number\n")
{
	struct e1inp_line *line;

	if (argc >= 1) {
		int num = atoi(argv[0]);
		llist_for_each_entry(line, &e1inp_line_list, list) {
			if (line->num == num) {
				e1line_dump_vty(vty, line);
				return CMD_SUCCESS;
			}
		}
		return CMD_WARNING;
	}	
	
	llist_for_each_entry(line, &e1inp_line_list, list)
		e1line_dump_vty(vty, line);

	return CMD_SUCCESS;
}

static void e1ts_dump_vty(struct vty *vty, struct e1inp_ts *ts)
{
	if (ts->type == E1INP_TS_TYPE_NONE)
		return;
	vty_out(vty, "E1 Timeslot %2u of Line %u is Type %s%s",
		ts->num, ts->line->num, e1inp_tstype_name(ts->type),
		VTY_NEWLINE);
}

DEFUN(show_e1ts,
      show_e1ts_cmd,
      "show e1_timeslot [line_nr] [ts_nr]",
	SHOW_STR "Display information about a E1 timeslot\n"
	"E1 Line Number\n" "E1 Timeslot Number\n")
{
	struct e1inp_line *line = NULL;
	struct e1inp_ts *ts;
	int ts_nr;

	if (argc == 0) {
		llist_for_each_entry(line, &e1inp_line_list, list) {
			for (ts_nr = 0; ts_nr < NUM_E1_TS; ts_nr++) {
				ts = &line->ts[ts_nr];
				e1ts_dump_vty(vty, ts);
			}
		}
		return CMD_SUCCESS;
	}
	if (argc >= 1) {
		int num = atoi(argv[0]);
		llist_for_each_entry(line, &e1inp_line_list, list) {
			if (line->num == num)
				break;
		}
		if (!line || line->num != num) {
			vty_out(vty, "E1 line %s is invalid%s",
				argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}	
	if (argc >= 2) {
		ts_nr = atoi(argv[1]);
		if (ts_nr > NUM_E1_TS) {
			vty_out(vty, "E1 timeslot %s is invalid%s",
				argv[1], VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &line->ts[ts_nr];
		e1ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	} else {
		for (ts_nr = 0; ts_nr < NUM_E1_TS; ts_nr++) {
			ts = &line->ts[ts_nr];
			e1ts_dump_vty(vty, ts);
		}
		return CMD_SUCCESS;
	}
	return CMD_SUCCESS;
}

static void paging_dump_vty(struct vty *vty, struct gsm_paging_request *pag)
{
	vty_out(vty, "Paging on BTS %u%s", pag->bts->nr, VTY_NEWLINE);
	subscr_dump_vty(vty, pag->subscr);
}

static void bts_paging_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_paging_request *pag;

	llist_for_each_entry(pag, &bts->paging.pending_requests, entry)
		paging_dump_vty(vty, pag);
}

DEFUN(show_paging,
      show_paging_cmd,
      "show paging [bts_nr]",
	SHOW_STR "Display information about paging reuqests of a BTS\n"
	"BTS Number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	int bts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);
		
		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);
	}

	return CMD_SUCCESS;
}

#define NETWORK_STR "Configure the GSM network\n"

DEFUN(cfg_net,
      cfg_net_cmd,
      "network", NETWORK_STR)
{
	vty->index = gsmnet_from_vty(vty);
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}


DEFUN(cfg_net_ncc,
      cfg_net_ncc_cmd,
      "network country code <1-999>",
      "Set the GSM network country code")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->country_code = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mnc,
      cfg_net_mnc_cmd,
      "mobile network code <1-999>",
      "Set the GSM mobile network code")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->network_code = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_short,
      cfg_net_name_short_cmd,
      "short name NAME",
      "Set the short GSM network name")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	if (gsmnet->name_short)
		talloc_free(gsmnet->name_short);

	gsmnet->name_short = talloc_strdup(gsmnet, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_long,
      cfg_net_name_long_cmd,
      "long name NAME",
      "Set the long GSM network name")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	if (gsmnet->name_long)
		talloc_free(gsmnet->name_long);

	gsmnet->name_long = talloc_strdup(gsmnet, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_auth_policy,
      cfg_net_auth_policy_cmd,
      "auth policy (closed|accept-all|token)",
	"Authentication (not cryptographic)\n"
	"Set the GSM network authentication policy\n"
	"Require the MS to be activated in HLR\n"
	"Accept all MS, whether in HLR or not\n"
	"Use SMS-token based authentication\n")
{
	enum gsm_auth_policy policy = gsm_auth_policy_parse(argv[0]);
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->auth_policy = policy;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_reject_cause,
      cfg_net_reject_cause_cmd,
      "location updating reject cause <2-111>",
      "Set the reject cause of location updating reject\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->reject_cause = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_encryption,
      cfg_net_encryption_cmd,
      "encryption a5 (0|1|2)",
	"Encryption options\n"
	"A5 encryption\n" "A5/0: No encryption\n"
	"A5/1: Encryption\n" "A5/2: Export-grade Encryption\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->a5_encryption= atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_neci,
      cfg_net_neci_cmd,
      "neci (0|1)",
	"New Establish Cause Indication\n"
	"Don't set the NECI bit\n" "Set the NECI bit\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->neci = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_rrlp_mode, cfg_net_rrlp_mode_cmd,
      "rrlp mode (none|ms-based|ms-preferred|ass-preferred)",
	"Radio Resource Location Protocol\n"
	"Set the Radio Resource Location Protocol Mode\n"
	"Don't send RRLP request\n"
	"Request MS-based location\n"
	"Request any location, prefer MS-based\n"
	"Request any location, prefer MS-assisted\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->rrlp.mode = rrlp_mode_parse(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mm_info, cfg_net_mm_info_cmd,
      "mm info (0|1)",
	"Whether to send MM INFO after LOC UPD ACCEPT")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->send_mm_info = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define HANDOVER_STR	"Handover Options\n"

DEFUN(cfg_net_handover, cfg_net_handover_cmd,
      "handover (0|1)",
	HANDOVER_STR
	"Don't perform in-call handover\n"
	"Perform in-call handover\n")
{
	int enable = atoi(argv[0]);
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	if (enable && ipacc_rtp_direct) {
		vty_out(vty, "%% Cannot enable handover unless RTP Proxy mode "
			"is enabled by using the -P command line option%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	gsmnet->handover.active = enable;

	return CMD_SUCCESS;
}

#define HO_WIN_STR HANDOVER_STR "Measurement Window\n"
#define HO_WIN_RXLEV_STR HO_WIN_STR "Received Level Averaging\n"
#define HO_WIN_RXQUAL_STR HO_WIN_STR "Received Quality Averaging\n"
#define HO_PBUDGET_STR HANDOVER_STR "Power Budget\n"

DEFUN(cfg_net_ho_win_rxlev_avg, cfg_net_ho_win_rxlev_avg_cmd,
      "handover window rxlev averaging <1-10>",
	HO_WIN_RXLEV_STR
	"How many RxLev measurements are used for averaging")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.win_rxlev_avg = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_win_rxqual_avg, cfg_net_ho_win_rxqual_avg_cmd,
      "handover window rxqual averaging <1-10>",
	HO_WIN_RXQUAL_STR
	"How many RxQual measurements are used for averaging")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.win_rxqual_avg = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_win_rxlev_neigh_avg, cfg_net_ho_win_rxlev_avg_neigh_cmd,
      "handover window rxlev neighbor averaging <1-10>",
	HO_WIN_RXLEV_STR
	"How many RxQual measurements are used for averaging")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.win_rxlev_avg_neigh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_pwr_interval, cfg_net_ho_pwr_interval_cmd,
      "handover power budget interval <1-99>",
	HO_PBUDGET_STR
	"How often to check if we have a better cell (SACCH frames)")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.pwr_interval = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_pwr_hysteresis, cfg_net_ho_pwr_hysteresis_cmd,
      "handover power budget hysteresis <0-999>",
	HO_PBUDGET_STR
	"How many dB does a neighbor to be stronger to become a HO candidate")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.pwr_hysteresis = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_max_distance, cfg_net_ho_max_distance_cmd,
      "handover maximum distance <0-9999>",
	HANDOVER_STR
	"How big is the maximum timing advance before HO is forced")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.max_distance = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_pag_any_tch,
      cfg_net_pag_any_tch_cmd,
      "paging any use tch (0|1)",
      "Assign a TCH when receiving a Paging Any request")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->pag_any_tch = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
	return CMD_SUCCESS;
}

#define DECLARE_TIMER(number, doc) \
    DEFUN(cfg_net_T##number,					\
      cfg_net_T##number##_cmd,					\
      "timer t" #number  " <0-65535>",				\
      "Configure GSM Timers\n"					\
      doc)							\
{								\
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);	\
	int value = atoi(argv[0]);				\
								\
	if (value < 0 || value > 65535) {			\
		vty_out(vty, "Timer value %s out of range.%s",	\
		        argv[0], VTY_NEWLINE);			\
		return CMD_WARNING;				\
	}							\
								\
	gsmnet->T##number = value;				\
	return CMD_SUCCESS;					\
}

DECLARE_TIMER(3101, "Set the timeout value for IMMEDIATE ASSIGNMENT.")
DECLARE_TIMER(3103, "Set the timeout value for HANDOVER.")
DECLARE_TIMER(3105, "Currently not used.")
DECLARE_TIMER(3107, "Currently not used.")
DECLARE_TIMER(3109, "Currently not used.")
DECLARE_TIMER(3111, "Set the RSL timeout to wait before releasing the RF Channel.")
DECLARE_TIMER(3113, "Set the time to try paging a subscriber.")
DECLARE_TIMER(3115, "Currently not used.")
DECLARE_TIMER(3117, "Currently not used.")
DECLARE_TIMER(3119, "Currently not used.")
DECLARE_TIMER(3141, "Currently not used.")

DEFUN(cfg_net_dtx,
      cfg_net_dtx_cmd,
      "dtx-used (0|1)",
      "Enable the usage of DTX.\n"
      "DTX is enabled/disabled")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->dtx_enabled = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* per-BTS configuration */
DEFUN(cfg_bts,
      cfg_bts_cmd,
      "bts BTS_NR",
      "Select a BTS to configure\n"
	"BTS Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr > gsmnet->num_bts) {
		vty_out(vty, "%% The next unused BTS number is %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bts_nr == gsmnet->num_bts) {
		/* allocate a new one */
		bts = gsm_bts_alloc(gsmnet, GSM_BTS_TYPE_UNKNOWN,
				    HARDCODED_TSC, HARDCODED_BSIC);
	} else
		bts = gsm_bts_num(gsmnet, bts_nr);

	if (!bts) {
		vty_out(vty, "%% Unable to allocate BTS %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = bts;
	vty->index_sub = &bts->description;
	vty->node = BTS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_type,
      cfg_bts_type_cmd,
      "type TYPE",
      "Set the BTS type\n")
{
	struct gsm_bts *bts = vty->index;
	int rc;

	rc = gsm_set_bts_type(bts, parse_btstype(argv[0]));
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_band,
      cfg_bts_band_cmd,
      "band BAND",
      "Set the frequency band of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int band = gsm_band_parse(argv[0]);

	if (band < 0) {
		vty_out(vty, "%% BAND %d is not a valid GSM band%s",
			band, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->band = band;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ci,
      cfg_bts_ci_cmd,
      "cell_identity <0-65535>",
      "Set the Cell identity of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int ci = atoi(argv[0]);

	if (ci < 0 || ci > 0xffff) {
		vty_out(vty, "%% CI %d is not in the valid range (0-65535)%s",
			ci, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->cell_identity = ci;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_lac,
      cfg_bts_lac_cmd,
      "location_area_code <0-65535>",
      "Set the Location Area Code (LAC) of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int lac = atoi(argv[0]);

	if (lac < 0 || lac > 0xffff) {
		vty_out(vty, "%% LAC %d is not in the valid range (0-65535)%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->location_area_code = lac;

	return CMD_SUCCESS;
}


DEFUN(cfg_bts_tsc,
      cfg_bts_tsc_cmd,
      "training_sequence_code <0-255>",
      "Set the Training Sequence Code (TSC) of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int tsc = atoi(argv[0]);

	if (tsc < 0 || tsc > 0xff) {
		vty_out(vty, "%% TSC %d is not in the valid range (0-255)%s",
			tsc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->tsc = tsc;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_bsic,
      cfg_bts_bsic_cmd,
      "base_station_id_code <0-63>",
      "Set the Base Station Identity Code (BSIC) of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int bsic = atoi(argv[0]);

	if (bsic < 0 || bsic > 0x3f) {
		vty_out(vty, "%% BSIC %d is not in the valid range (0-255)%s",
			bsic, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->bsic = bsic;

	return CMD_SUCCESS;
}


DEFUN(cfg_bts_unit_id,
      cfg_bts_unit_id_cmd,
      "ip.access unit_id <0-65534> <0-255>",
      "Set the ip.access BTS Unit ID of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int site_id = atoi(argv[0]);
	int bts_id = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->ip_access.site_id = site_id;
	bts->ip_access.bts_id = bts_id;

	return CMD_SUCCESS;
}

#define OML_STR	"Organization & Maintenance Link\n"
#define IPA_STR "ip.access Specific Options\n"

DEFUN(cfg_bts_stream_id,
      cfg_bts_stream_id_cmd,
      "oml ip.access stream_id <0-255>",
	OML_STR IPA_STR
      "Set the ip.access Stream ID of the OML link of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int stream_id = atoi(argv[0]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->oml_tei = stream_id;

	return CMD_SUCCESS;
}

#define OML_E1_STR OML_STR "E1 Line\n"

DEFUN(cfg_bts_oml_e1,
      cfg_bts_oml_e1_cmd,
      "oml e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
	OML_E1_STR
      "E1 interface to be used for OML\n")
{
	struct gsm_bts *bts = vty->index;

	parse_e1_link(&bts->oml_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}


DEFUN(cfg_bts_oml_e1_tei,
      cfg_bts_oml_e1_tei_cmd,
      "oml e1 tei <0-63>",
	OML_E1_STR
      "Set the TEI to be used for OML")
{
	struct gsm_bts *bts = vty->index;

	bts->oml_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_challoc, cfg_bts_challoc_cmd,
      "channel allocator (ascending|descending)",
	"Channnel Allocator\n" "Channel Allocator\n"
	"Allocate Timeslots and Transceivers in ascending order\n"
	"Allocate Timeslots and Transceivers in descending order\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "ascending"))
		bts->chan_alloc_reverse = 0;
	else
		bts->chan_alloc_reverse = 1;

	return CMD_SUCCESS;
}

#define RACH_STR "Random Access Control Channel\n"

DEFUN(cfg_bts_rach_tx_integer,
      cfg_bts_rach_tx_integer_cmd,
      "rach tx integer <0-15>",
	RACH_STR
      "Set the raw tx integer value in RACH Control parameters IE")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.tx_integer = atoi(argv[0]) & 0xf;
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_max_trans,
      cfg_bts_rach_max_trans_cmd,
      "rach max transmission (1|2|4|7)",
	RACH_STR
      "Set the maximum number of RACH burst transmissions")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.max_trans = rach_max_trans_val2raw(atoi(argv[0]));
	return CMD_SUCCESS;
}

#define NM_STR "Network Management\n"

DEFUN(cfg_bts_rach_nm_b_thresh,
      cfg_bts_rach_nm_b_thresh_cmd,
      "rach nm busy threshold <0-255>",
	RACH_STR NM_STR
      "Set the NM Busy Threshold in dB")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_b_thresh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_nm_ldavg,
      cfg_bts_rach_nm_ldavg_cmd,
      "rach nm load average <0-65535>",
	RACH_STR NM_STR
      "Set the NM Loadaverage Slots value")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_ldavg_slots = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cell_barred, cfg_bts_cell_barred_cmd,
      "cell barred (0|1)",
      "Should this cell be barred from access?")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.rach_control.cell_bar = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_ec_allowed, cfg_bts_rach_ec_allowed_cmd,
      "rach emergency call allowed (0|1)",
      "Should this cell allow emergency calls?")
{
	struct gsm_bts *bts = vty->index;

	if (atoi(argv[0]) == 0)
		bts->si_common.rach_control.t2 |= 0x4;
	else
		bts->si_common.rach_control.t2 &= ~0x4;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ms_max_power, cfg_bts_ms_max_power_cmd,
      "ms max power <0-40>",
      "Maximum transmit power of the MS")
{
	struct gsm_bts *bts = vty->index;

	bts->ms_max_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cell_resel_hyst, cfg_bts_cell_resel_hyst_cmd,
      "cell reselection hysteresis <0-14>",
      "Cell Re-Selection Hysteresis in dB")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.cell_resel_hyst = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rxlev_acc_min, cfg_bts_rxlev_acc_min_cmd,
      "rxlev access min <0-63>",
      "Minimum RxLev needed for cell access (better than -110dBm)")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.rxlev_acc_min = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_per_loc_upd, cfg_bts_per_loc_upd_cmd,
      "periodic location update <0-1530>",
      "Periodic Location Updating Interval in Minutes")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.chan_desc.t3212 = atoi(argv[0]) / 10;

	return CMD_SUCCESS;
}

#define GPRS_TEXT	"GPRS Packet Network\n"

DEFUN(cfg_bts_prs_bvci, cfg_bts_gprs_bvci_cmd,
	"gprs cell bvci <2-65535>",
	GPRS_TEXT
	"GPRS Cell Settings\n"
	"GPRS BSSGP VC Identifier")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.cell.bvci = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsei, cfg_bts_gprs_nsei_cmd,
	"gprs nsei <0-65535>",
	GPRS_TEXT
	"GPRS NS Entity Identifier")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nse.nsei = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define NSVC_TEXT "Network Service Virtual Connection (NS-VC)\n" \
		"NSVC Logical Number\n"

DEFUN(cfg_bts_gprs_nsvci, cfg_bts_gprs_nsvci_cmd,
	"gprs nsvc <0-1> nsvci <0-65535>",
	GPRS_TEXT NSVC_TEXT
	"NS Virtual Connection Identifier\n"
	"GPRS NS VC Identifier")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nsvc[idx].nsvci = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsvc_lport, cfg_bts_gprs_nsvc_lport_cmd,
	"gprs nsvc <0-1> local udp port <0-65535>",
	GPRS_TEXT NSVC_TEXT
	"GPRS NS Local UDP Port")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nsvc[idx].local_port = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsvc_rport, cfg_bts_gprs_nsvc_rport_cmd,
	"gprs nsvc <0-1> remote udp port <0-65535>",
	GPRS_TEXT NSVC_TEXT
	"GPRS NS Remote UDP Port")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nsvc[idx].remote_port = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsvc_rip, cfg_bts_gprs_nsvc_rip_cmd,
	"gprs nsvc <0-1> remote ip A.B.C.D",
	GPRS_TEXT NSVC_TEXT
	"GPRS NS Remote IP Address")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);
	struct in_addr ia;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	inet_aton(argv[1], &ia);
	bts->gprs.nsvc[idx].remote_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_pag_free, cfg_bts_pag_free_cmd,
      "paging free FREE_NR",
      "Only page when having a certain amount of free slots. -1 to disable")
{
	struct gsm_bts *bts = vty->index;

	bts->paging.free_chans_need = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_ns_timer, cfg_bts_gprs_ns_timer_cmd,
	"gprs ns timer " NS_TIMERS " <0-255>",
	GPRS_TEXT "Network Service\n"
	"Network Service Timer\n"
	NS_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_ns_timer_strs, argv[0]);
	int val = atoi(argv[1]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (idx < 0 || idx >= ARRAY_SIZE(bts->gprs.nse.timer))
		return CMD_WARNING;

	bts->gprs.nse.timer[idx] = val;

	return CMD_SUCCESS;
}

#define BSSGP_TIMERS "(blocking-timer|blocking-retries|unblocking-retries|reset-timer|reset-retries|suspend-timer|suspend-retries|resume-timer|resume-retries|capability-update-timer|capability-update-retries)"
#define BSSGP_TIMERS_HELP	\
	"Tbvc-block timeout\n"			\
	"Tbvc-block retries\n"			\
	"Tbvc-unblock retries\n"		\
	"Tbvcc-reset timeout\n"			\
	"Tbvc-reset retries\n"			\
	"Tbvc-suspend timeout\n"		\
	"Tbvc-suspend retries\n"		\
	"Tbvc-resume timeout\n"			\
	"Tbvc-resume retries\n"			\
	"Tbvc-capa-update timeout\n"		\
	"Tbvc-capa-update retries\n"

DEFUN(cfg_bts_gprs_cell_timer, cfg_bts_gprs_cell_timer_cmd,
	"gprs cell timer " BSSGP_TIMERS " <0-255>",
	GPRS_TEXT "Cell / BSSGP\n"
	"Cell/BSSGP Timer\n"
	BSSGP_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_bssgp_cfg_strs, argv[0]);
	int val = atoi(argv[1]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (idx < 0 || idx >= ARRAY_SIZE(bts->gprs.cell.timer))
		return CMD_WARNING;

	bts->gprs.cell.timer[idx] = val;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_rac, cfg_bts_gprs_rac_cmd,
	"gprs routing area <0-255>",
	GPRS_TEXT
	"GPRS Routing Area Code")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.rac = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_mode, cfg_bts_gprs_mode_cmd,
	"gprs mode (none|gprs|egprs)",
	GPRS_TEXT
	"GPRS Mode for this BTS\n"
	"GPRS Disabled on this BTS\n"
	"GPRS Enabled on this BTS\n"
	"EGPRS (EDGE) Enabled on this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	enum bts_gprs_mode mode = bts_gprs_mode_parse(argv[0]);

	if (mode != BTS_GPRS_NONE &&
	    !gsm_bts_has_feature(bts, BTS_FEAT_GPRS)) {
		vty_out(vty, "This BTS type does not support %s%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (mode == BTS_GPRS_EGPRS &&
	    !gsm_bts_has_feature(bts, BTS_FEAT_EGPRS)) {
		vty_out(vty, "This BTS type does not support %s%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.mode = mode;

	return CMD_SUCCESS;
}

#define SI_TEXT		"System Information Messages\n"
#define SI_TYPE_TEXT "(1|2|3|4|5|6|7|8|9|10|13|16|17|18|19|20|2bis|2ter|2quater|5bis|5ter)"
#define SI_TYPE_HELP 	"System Information Type 1\n"	\
			"System Information Type 2\n"	\
			"System Information Type 3\n"	\
			"System Information Type 4\n"	\
			"System Information Type 5\n"	\
			"System Information Type 6\n"	\
			"System Information Type 7\n"	\
			"System Information Type 8\n"	\
			"System Information Type 9\n"	\
			"System Information Type 10\n"	\
			"System Information Type 13\n"	\
			"System Information Type 16\n"	\
			"System Information Type 17\n"	\
			"System Information Type 18\n"	\
			"System Information Type 19\n"	\
			"System Information Type 20\n"	\
			"System Information Type 2bis\n"	\
			"System Information Type 2ter\n"	\
			"System Information Type 2quater\n"	\
			"System Information Type 5bis\n"	\
			"System Information Type 5ter\n"

DEFUN(cfg_bts_si_mode, cfg_bts_si_mode_cmd,
	"system-information " SI_TYPE_TEXT " mode (static|computed)",
	SI_TEXT SI_TYPE_HELP
	"System Information Mode\n"
	"Static user-specified\n"
	"Dynamic, BSC-computed\n")
{
	struct gsm_bts *bts = vty->index;
	int type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "static"))
		bts->si_mode_static |= (1 << type);
	else
		bts->si_mode_static &= ~(1 << type);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_si_static, cfg_bts_si_static_cmd,
	"system-information " SI_TYPE_TEXT " static HEXSTRING",
	SI_TEXT SI_TYPE_HELP
	"Static System Information filling\n"
	"Static user-specified SI content in HEX notation\n")
{
	struct gsm_bts *bts = vty->index;
	int rc, type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!(bts->si_mode_static & (1 << type))) {
		vty_out(vty, "SI Type %s is not configured in static mode%s",
			get_value_string(osmo_sitype_strs, type), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Fill buffer with padding pattern */
	memset(bts->si_buf[type], 0x2b, sizeof(bts->si_buf[type]));

	/* Parse the user-specified SI in hex format, [partially] overwriting padding */
	rc = hexparse(argv[1], bts->si_buf[type], sizeof(bts->si_buf[0]));
	if (rc < 0 || rc > sizeof(bts->si_buf[0])) {
		vty_out(vty, "Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Mark this SI as present */
	bts->si_valid |= (1 << type);

	return CMD_SUCCESS;
}


#define TRX_TEXT "Radio Transceiver\n"

/* per TRX configuration */
DEFUN(cfg_trx,
      cfg_trx_cmd,
      "trx TRX_NR",
	TRX_TEXT
      "Select a TRX to configure")
{
	int trx_nr = atoi(argv[0]);
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_trx *trx;

	if (trx_nr > bts->num_trx) {
		vty_out(vty, "%% The next unused TRX number in this BTS is %u%s",
			bts->num_trx, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (trx_nr == bts->num_trx) {
		/* we need to allocate a new one */
		trx = gsm_bts_trx_alloc(bts);
	} else
		trx = gsm_bts_trx_num(bts, trx_nr);

	if (!trx)
		return CMD_WARNING;

	vty->index = trx;
	vty->index_sub = &trx->description;
	vty->node = TRX_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_arfcn,
      cfg_trx_arfcn_cmd,
      "arfcn <0-1024>",
      "Set the ARFCN for this TRX\n")
{
	int arfcn = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;

	/* FIXME: check if this ARFCN is supported by this TRX */

	trx->arfcn = arfcn;

	/* FIXME: patch ARFCN into SYSTEM INFORMATION */
	/* FIXME: use OML layer to update the ARFCN */
	/* FIXME: use RSL layer to update SYSTEM INFORMATION */

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_nominal_power,
      cfg_trx_nominal_power_cmd,
      "nominal power <0-100>",
      "Nominal TRX RF Power in dB\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->nominal_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_max_power_red,
      cfg_trx_max_power_red_cmd,
      "max_power_red <0-100>",
      "Reduction of maximum BS RF Power in dB\n")
{
	int maxpwr_r = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	int upper_limit = 24;	/* default 12.21 max power red. */

	/* FIXME: check if our BTS type supports more than 12 */
	if (maxpwr_r < 0 || maxpwr_r > upper_limit) {
		vty_out(vty, "%% Power %d dB is not in the valid range%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (maxpwr_r & 1) {
		vty_out(vty, "%% Power %d dB is not an even value%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx->max_power_red = maxpwr_r;

	/* FIXME: make sure we update this using OML */

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rsl_e1,
      cfg_trx_rsl_e1_cmd,
      "rsl e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "E1 interface to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	parse_e1_link(&trx->rsl_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rsl_e1_tei,
      cfg_trx_rsl_e1_tei_cmd,
      "rsl e1 tei <0-63>",
      "Set the TEI to be used for RSL")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->rsl_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rf_locked,
      cfg_trx_rf_locked_cmd,
      "rf_locked (0|1)",
      "Turn off RF of the TRX.\n")
{
	int locked = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;

	gsm_trx_lock_rf(trx, locked);
	return CMD_SUCCESS;
}

/* per TS configuration */
DEFUN(cfg_ts,
      cfg_ts_cmd,
      "timeslot <0-7>",
      "Select a Timeslot to configure")
{
	int ts_nr = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	struct gsm_bts_trx_ts *ts;

	if (ts_nr >= TRX_NR_TS) {
		vty_out(vty, "%% A GSM TRX only has %u Timeslots per TRX%s",
			TRX_NR_TS, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts = &trx->ts[ts_nr];

	vty->index = ts;
	vty->node = TS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_pchan,
      cfg_ts_pchan_cmd,
      "phys_chan_config PCHAN",
      "Physical Channel configuration (TCH/SDCCH/...)")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0)
		return CMD_WARNING;

	ts->pchan = pchanc;

	return CMD_SUCCESS;
}

#define HOPPING_STR "Configure frequency hopping\n"

DEFUN(cfg_ts_hopping,
      cfg_ts_hopping_cmd,
      "hopping enabled (0|1)",
	HOPPING_STR "Enable or disable frequency hopping\n"
      "Disable frequency hopping\n" "Enable frequency hopping\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int enabled = atoi(argv[0]);

	if (enabled && !gsm_bts_has_feature(ts->trx->bts, BTS_FEAT_HOPPING)) {
		vty_out(vty, "BTS model does not support hopping%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts->hopping.enabled = enabled;

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_hsn,
      cfg_ts_hsn_cmd,
      "hopping sequence-number <0-63>",
	HOPPING_STR
      "Which hopping sequence to use for this channel")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.hsn = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_maio,
      cfg_ts_maio_cmd,
      "hopping maio <0-63>",
	HOPPING_STR
      "Which hopping MAIO to use for this channel")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.maio = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_arfcn_add,
      cfg_ts_arfcn_add_cmd,
      "hopping arfcn add <0-1023>",
	HOPPING_STR "Configure hopping ARFCN list\n"
      "Add an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 1);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_arfcn_del,
      cfg_ts_arfcn_del_cmd,
      "hopping arfcn del <0-1023>",
	HOPPING_STR "Configure hopping ARFCN list\n"
      "Delete an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_e1_subslot,
      cfg_ts_e1_subslot_cmd,
      "e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "E1 sub-slot connected to this on-air timeslot")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	parse_e1_link(&ts->e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *net)
{
	vty_out(vty, "Channel Requests        : %lu total, %lu no channel%s",
		counter_get(net->stats.chreq.total),
		counter_get(net->stats.chreq.no_channel), VTY_NEWLINE);
	vty_out(vty, "Channel Failures        : %lu rf_failures, %lu rll failures%s",
		counter_get(net->stats.chan.rf_fail),
		counter_get(net->stats.chan.rll_err), VTY_NEWLINE);
	vty_out(vty, "Paging                  : %lu attempted, %lu complete, %lu expired%s",
		counter_get(net->stats.paging.attempted),
		counter_get(net->stats.paging.completed),
		counter_get(net->stats.paging.expired), VTY_NEWLINE);
	vty_out(vty, "BTS failures            : %lu OML, %lu RSL%s",
		counter_get(net->stats.bts.oml_fail),
		counter_get(net->stats.bts.rsl_fail), VTY_NEWLINE);
}

DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_imsi_filter(conn->dbg, argv[0]);
	return CMD_SUCCESS;
}

extern int bsc_vty_init_extra(void);
extern const char *openbsc_copyright;

int bsc_vty_init(void)
{
	install_element_ve(&show_net_cmd);
	install_element_ve(&show_bts_cmd);
	install_element_ve(&show_trx_cmd);
	install_element_ve(&show_ts_cmd);
	install_element_ve(&show_lchan_cmd);
	install_element_ve(&show_lchan_summary_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);

	install_element_ve(&show_e1drv_cmd);
	install_element_ve(&show_e1line_cmd);
	install_element_ve(&show_e1ts_cmd);

	install_element_ve(&show_paging_cmd);

	logging_vty_add_cmds();

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	install_default(GSMNET_NODE);
	install_element(GSMNET_NODE, &ournode_exit_cmd);
	install_element(GSMNET_NODE, &ournode_end_cmd);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_short_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_long_cmd);
	install_element(GSMNET_NODE, &cfg_net_auth_policy_cmd);
	install_element(GSMNET_NODE, &cfg_net_reject_cause_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_neci_cmd);
	install_element(GSMNET_NODE, &cfg_net_rrlp_mode_cmd);
	install_element(GSMNET_NODE, &cfg_net_mm_info_cmd);
	install_element(GSMNET_NODE, &cfg_net_handover_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_win_rxlev_avg_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_win_rxqual_avg_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_win_rxlev_avg_neigh_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_pwr_interval_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_pwr_hysteresis_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_max_distance_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3101_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3103_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3105_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3107_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3109_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3111_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3113_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3115_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3117_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3119_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3141_cmd);
	install_element(GSMNET_NODE, &cfg_net_dtx_cmd);
	install_element(GSMNET_NODE, &cfg_net_pag_any_tch_cmd);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node, config_write_bts);
	install_default(BTS_NODE);
	install_element(BTS_NODE, &ournode_exit_cmd);
	install_element(BTS_NODE, &ournode_end_cmd);
	install_element(BTS_NODE, &cfg_bts_type_cmd);
	install_element(BTS_NODE, &cfg_description_cmd);
	install_element(BTS_NODE, &cfg_no_description_cmd);
	install_element(BTS_NODE, &cfg_bts_band_cmd);
	install_element(BTS_NODE, &cfg_bts_ci_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_tsc_cmd);
	install_element(BTS_NODE, &cfg_bts_bsic_cmd);
	install_element(BTS_NODE, &cfg_bts_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_tei_cmd);
	install_element(BTS_NODE, &cfg_bts_challoc_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_tx_integer_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_max_trans_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_b_thresh_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_ldavg_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_barred_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ec_allowed_cmd);
	install_element(BTS_NODE, &cfg_bts_ms_max_power_cmd);
	install_element(BTS_NODE, &cfg_bts_per_loc_upd_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_hyst_cmd);
	install_element(BTS_NODE, &cfg_bts_rxlev_acc_min_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ns_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_rac_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_bvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_cell_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsei_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_lport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rip_cmd);
	install_element(BTS_NODE, &cfg_bts_pag_free_cmd);
	install_element(BTS_NODE, &cfg_bts_si_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_si_static_cmd);

	install_element(BTS_NODE, &cfg_trx_cmd);
	install_node(&trx_node, dummy_config_write);
	install_default(TRX_NODE);
	install_element(TRX_NODE, &ournode_exit_cmd);
	install_element(TRX_NODE, &ournode_end_cmd);
	install_element(TRX_NODE, &cfg_trx_arfcn_cmd);
	install_element(TRX_NODE, &cfg_description_cmd);
	install_element(TRX_NODE, &cfg_no_description_cmd);
	install_element(TRX_NODE, &cfg_trx_nominal_power_cmd);
	install_element(TRX_NODE, &cfg_trx_max_power_red_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_tei_cmd);
	install_element(TRX_NODE, &cfg_trx_rf_locked_cmd);

	install_element(TRX_NODE, &cfg_ts_cmd);
	install_node(&ts_node, dummy_config_write);
	install_default(TS_NODE);
	install_element(TS_NODE, &ournode_exit_cmd);
	install_element(TS_NODE, &ournode_end_cmd);
	install_element(TS_NODE, &cfg_ts_pchan_cmd);
	install_element(TS_NODE, &cfg_ts_hopping_cmd);
	install_element(TS_NODE, &cfg_ts_hsn_cmd);
	install_element(TS_NODE, &cfg_ts_maio_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_add_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_del_cmd);
	install_element(TS_NODE, &cfg_ts_e1_subslot_cmd);

	abis_nm_vty_init();

	bsc_vty_init_extra();

	return 0;
}