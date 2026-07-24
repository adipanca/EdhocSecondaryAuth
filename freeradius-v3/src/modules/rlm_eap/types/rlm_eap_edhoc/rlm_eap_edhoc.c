/*
 * rlm_eap_edhoc.c    EAP-EDHOC method 4 (SIGMA XWING) responder.
 *
 * FreeRADIUS EAP sub-module implementing the DN-AAA (responder) side of the
 * "EAP-EDHOC Hybrid PQC (XWING) — SIGMA" handshake from mermaid.md §5.
 *
 * The cryptographic core (libedhoc4) is shared byte-for-byte with the UERANSIM
 * UE initiator, guaranteeing interoperability.
 *
 * EAP message flow (server = EDHOC responder, peer = EDHOC initiator):
 *   server -> peer : EAP-Request/EDHOC  (start, 1 byte 0x01)
 *   peer   -> server: EAP-Response/EDHOC (message_1)
 *   server -> peer : EAP-Request/EDHOC  (message_2)
 *   peer   -> server: EAP-Response/EDHOC (message_3)
 *   server -> peer : EAP-Request/EDHOC  (message_4)
 *   peer   -> server: EAP-Response/EDHOC (empty ACK)
 *   server -> peer : EAP-Success  (+ MS-MPPE keys derived from MSK)
 */
RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "eap.h"

#include <freeradius-devel/rad_assert.h>

#include "edhoc4.h"
#include "edhoc03.h"

typedef struct rlm_eap_edhoc_t {
	char const	*creds_path;	//!< server.creds (responder credentials, method 4)
	char const	*peer_pub_path;	//!< ue.pub (UE static XWING public key, method 4)
	char const	*creds03_path;	//!< server03.creds (responder creds, methods 0-3)
	char const	*peer_pub03_path; //!< ue03.pub (UE static keys, methods 0-3)
	edhoc4_creds	server;
	uint8_t		ue_pub[E4_XWING_PK];
	edhoc03_creds	server03;
	edhoc03_peer	ue03_pub;
	int		have03;		//!< classical creds loaded
} rlm_eap_edhoc_t;

typedef struct edhoc_session_t {
	edhoc4_ctx	ctx;		//!< method 4 state
	edhoc03_ctx	ctx03;		//!< methods 0-3 state
	int		mode;		//!< 0 = undetermined, 3 = classical, 4 = pqc
	int		round;		//!< 0 = start sent, 1 = msg2 sent, 2 = msg4 sent
	uint8_t		in[E4_MAX_MSG];
	size_t		in_len;
	size_t		in_pos;
	uint8_t		out[E4_MAX_MSG];
	size_t		out_len;
	size_t		out_pos;
} edhoc_session_t;

static CONF_PARSER module_config[] = {
	{ "creds", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_FILE_INPUT, rlm_eap_edhoc_t, creds_path), NULL },
	{ "peer_pub", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_FILE_INPUT, rlm_eap_edhoc_t, peer_pub_path), NULL },
	{ "creds03", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_FILE_INPUT, rlm_eap_edhoc_t, creds03_path), NULL },
	{ "peer_pub03", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_FILE_INPUT, rlm_eap_edhoc_t, peer_pub03_path), NULL },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_edhoc_t *inst;

	*instance = inst = talloc_zero(cs, rlm_eap_edhoc_t);
	if (!inst) return -1;

	if (cf_section_parse(cs, inst, module_config) < 0) return -1;

	if (!inst->creds_path || !inst->peer_pub_path) {
		ERROR("rlm_eap_edhoc: 'creds' and 'peer_pub' must be configured");
		return -1;
	}

	if (edhoc4_creds_load(inst->creds_path, &inst->server) != E4_OK) {
		ERROR("rlm_eap_edhoc: failed to load responder creds from %s", inst->creds_path);
		return -1;
	}
	if (edhoc4_pub_load(inst->peer_pub_path, inst->ue_pub) != E4_OK) {
		ERROR("rlm_eap_edhoc: failed to load peer public key from %s", inst->peer_pub_path);
		return -1;
	}

	INFO("rlm_eap_edhoc: loaded method-4 SIGMA XWING credentials");

	/* Classical methods 0-3 credentials are optional. */
	if (inst->creds03_path && inst->peer_pub03_path) {
		if (edhoc03_creds_load(inst->creds03_path, &inst->server03) != E3_OK) {
			ERROR("rlm_eap_edhoc: failed to load classical creds from %s", inst->creds03_path);
			return -1;
		}
		if (edhoc03_pub_load(inst->peer_pub03_path, &inst->ue03_pub) != E3_OK) {
			ERROR("rlm_eap_edhoc: failed to load classical peer key from %s", inst->peer_pub03_path);
			return -1;
		}
		inst->have03 = 1;
		INFO("rlm_eap_edhoc: loaded classical methods 0-3 credentials");
	}
	return 0;
}

/*
 *	Send EAP-Request/EDHOC start; the peer replies with message_1.
 */
static int mod_session_init(void *instance, eap_handler_t *handler)
{
	EAP_DS		*eap_ds = handler->eap_ds;
	edhoc_session_t	*sess;

	(void) instance;

	sess = talloc_zero(handler, edhoc_session_t);
	if (!sess) return 0;

	/* Responder core is chosen once message_1 reveals the method. */
	sess->mode = 0;
	sess->round = 0;
	sess->in_len = 0;
	sess->in_pos = 0;
	sess->out_len = 0;
	sess->out_pos = 0;

	handler->opaque = sess;
	handler->free_opaque = NULL;	/* talloc'd under handler */

	eap_ds->request->code = PW_EAP_REQUEST;
	eap_ds->request->type.num = PW_EAP_EDHOC;
	eap_ds->request->type.data = talloc_array(eap_ds->request, uint8_t, 1);
	if (!eap_ds->request->type.data) return 0;
	eap_ds->request->type.data[0] = 0x01;	/* EDHOC-Start */
	eap_ds->request->type.length = 1;

	handler->stage = PROCESS;
	return 1;
}

static int edhoc_emit_eap(EAP_DS *eap_ds, uint8_t code, const uint8_t *buf, size_t len)
{
	eap_ds->request->code = code;
	eap_ds->request->type.num = PW_EAP_EDHOC;
	eap_ds->request->type.data = talloc_array(eap_ds->request, uint8_t, len);
	if (!eap_ds->request->type.data) return 0;
	memcpy(eap_ds->request->type.data, buf, len);
	eap_ds->request->type.length = len;
	return 1;
}

static int edhoc_send_ack(EAP_DS *eap_ds, uint8_t code)
{
	uint8_t ack = 0x00;

	return edhoc_emit_eap(eap_ds, code, &ack, sizeof(ack));
}

static int edhoc_send_fragment(EAP_DS *eap_ds, edhoc_session_t *sess, uint8_t code)
{
	const size_t first_cap = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN - E4_EDHOC_FRAG_LEN_LEN;
	const size_t next_cap = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN;
	size_t remaining = sess->out_len - sess->out_pos;
	size_t frag_cap = (sess->out_pos == 0) ? first_cap : next_cap;
	size_t frag_len = remaining < frag_cap ? remaining : frag_cap;
	size_t wire_len = E4_EDHOC_FRAG_HDR_LEN + ((sess->out_pos == 0 && remaining > frag_len) ? E4_EDHOC_FRAG_LEN_LEN : 0) + frag_len;
	uint8_t *wire;
	size_t pos = 0;

	if (remaining == 0)
		return 0;

	wire = talloc_array(eap_ds->request, uint8_t, wire_len);
	if (!wire)
		return 0;

	wire[pos++] = (remaining > frag_len ? E4_EDHOC_FRAG_FLAG_MORE : 0) |
		      ((sess->out_pos == 0 && remaining > frag_len) ? E4_EDHOC_FRAG_FLAG_LEN : 0);
	if (sess->out_pos == 0 && remaining > frag_len) {
		uint16_t total = htons((uint16_t)sess->out_len);
		memcpy(wire + pos, &total, sizeof(total));
		pos += sizeof(total);
	}

	memcpy(wire + pos, sess->out + sess->out_pos, frag_len);
	sess->out_pos += frag_len;
	if (sess->out_pos >= sess->out_len) {
		sess->out_len = 0;
		sess->out_pos = 0;
	}

	return edhoc_emit_eap(eap_ds, code, wire, wire_len);
}

static int edhoc_queue_outgoing(EAP_DS *eap_ds, edhoc_session_t *sess, uint8_t code,
				    const uint8_t *buf, size_t len)
{
	const size_t first_cap = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN - E4_EDHOC_FRAG_LEN_LEN;

	if (len == 0)
		return edhoc_send_ack(eap_ds, code);

	if (len <= first_cap) {
		uint8_t wire[E4_MAX_MSG + E4_EDHOC_FRAG_HDR_LEN] = {0};

		wire[0] = 0x00;
		memcpy(wire + 1, buf, len);
		return edhoc_emit_eap(eap_ds, code, wire, len + 1);
	}

	if (len > sizeof(sess->out)) {
		ERROR("rlm_eap_edhoc: outgoing payload too large (%zu)", len);
		return 0;
	}

	memcpy(sess->out, buf, len);
	sess->out_len = len;
	sess->out_pos = 0;
	return edhoc_send_fragment(eap_ds, sess, code);
}

static int edhoc_consume_incoming(edhoc_session_t *sess, const uint8_t *in, size_t in_len,
				  const uint8_t **msg, size_t *msg_len, int *need_ack)
{
	uint8_t flags;
	size_t pos = 0;

	*need_ack = 0;
	*msg = NULL;
	*msg_len = 0;

	if (!in || in_len == 0)
		return E4_ERR_PARSE;

	flags = in[pos++];
	if (flags & E4_EDHOC_FRAG_FLAG_LEN) {
		uint16_t total = 0;

		if (in_len < E4_EDHOC_FRAG_HDR_LEN + E4_EDHOC_FRAG_LEN_LEN)
			return E4_ERR_PARSE;
		memcpy(&total, in + pos, sizeof(total));
		total = ntohs(total);
		pos += sizeof(total);
		if (total == 0 || total > E4_MAX_MSG)
			return E4_ERR_BUF;
		if (!sess->in_len) {
			sess->in_len = total;
			sess->in_pos = 0;
		} else if (sess->in_len != total) {
			return E4_ERR_PARSE;
		}
	}

	if (in_len < pos)
		return E4_ERR_PARSE;

	if (sess->in_len) {
		size_t payload_len = in_len - pos;

		if (sess->in_pos + payload_len > sess->in_len)
			return E4_ERR_BUF;
		memcpy(sess->in + sess->in_pos, in + pos, payload_len);
		sess->in_pos += payload_len;
		if (flags & E4_EDHOC_FRAG_FLAG_MORE) {
			*need_ack = 1;
			return E4_OK;
		}
		if (sess->in_pos != sess->in_len)
			return E4_ERR_PARSE;
		*msg = sess->in;
		*msg_len = sess->in_len;
		sess->in_len = 0;
		sess->in_pos = 0;
		return E4_OK;
	}

	if (flags & E4_EDHOC_FRAG_FLAG_MORE)
		return E4_ERR_PARSE;

	*msg = in + pos;
	*msg_len = in_len - pos;
	return E4_OK;
}

static int CC_HINT(nonnull) mod_process(void *instance, eap_handler_t *handler)
{
	EAP_DS		*eap_ds = handler->eap_ds;
	edhoc_session_t	*sess = handler->opaque;
	REQUEST		*request = handler->request;
	uint8_t		out[E4_MAX_MSG];
	size_t		out_len = 0;
	const uint8_t	*in = eap_ds->response->type.data;
	size_t		in_len = eap_ds->response->type.length;
	const uint8_t	*msg = NULL;
	size_t		msg_len = 0;
	int		need_ack = 0;
	int		rc;

	(void) instance;
	rad_assert(handler->stage == PROCESS);

	if (!sess) {
		REDEBUG("rlm_eap_edhoc: missing session state");
		eap_ds->request->code = PW_EAP_FAILURE;
		return 0;
	}

	if (sess->out_pos < sess->out_len) {
		if (!edhoc_send_fragment(eap_ds, sess, PW_EAP_REQUEST)) {
			REDEBUG("rlm_eap_edhoc: failed to continue fragmented send");
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}
		RDEBUG2("rlm_eap_edhoc: continued outgoing fragment (%zu bytes remaining)",
			sess->out_len - sess->out_pos);
		return 1;
	}

	rc = edhoc_consume_incoming(sess, in, in_len, &msg, &msg_len, &need_ack);
	if (rc != E4_OK) {
		REDEBUG("rlm_eap_edhoc: fragment parse failed: %s", edhoc4_strerror(rc));
		eap_ds->request->code = PW_EAP_FAILURE;
		return 0;
	}

	if (need_ack) {
		if (!edhoc_send_ack(eap_ds, PW_EAP_REQUEST)) {
			REDEBUG("rlm_eap_edhoc: failed to ACK incoming fragment");
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}
		RDEBUG2("rlm_eap_edhoc: ACKed incoming fragment (%zu bytes buffered)", sess->in_pos);
		return 1;
	}

	switch (sess->round) {
	case 0:	/* expect message_1 -> build message_2 */
		if (sess->mode == 0) {
			if (msg_len == (size_t)(1 + E3_X_PK + E3_CONN_ID) && msg[0] <= 3) {
				sess->mode = 3;
			} else {
				sess->mode = 4;
			}
		}
		if (sess->mode == 3) {
			rlm_eap_edhoc_t *inst3 = (rlm_eap_edhoc_t *) instance;
			if (!inst3->have03) {
				REDEBUG("rlm_eap_edhoc: classical method requested but creds03 not configured");
				eap_ds->request->code = PW_EAP_FAILURE;
				return 0;
			}
			edhoc03_init_responder(&sess->ctx03, &inst3->server03, &inst3->ue03_pub);
			rc = edhoc03_r_handle_msg1(&sess->ctx03, msg, msg_len, out, sizeof(out), &out_len);
			if (rc != E3_OK) {
				REDEBUG("rlm_eap_edhoc: message_1 (classical) failed: %s", edhoc03_strerror(rc));
				eap_ds->request->code = PW_EAP_FAILURE;
				return 0;
			}
		} else {
			rlm_eap_edhoc_t *inst4 = (rlm_eap_edhoc_t *) instance;
			edhoc4_init_responder(&sess->ctx, &inst4->server, inst4->ue_pub);
			rc = edhoc4_r_handle_msg1(&sess->ctx, msg, msg_len, out, sizeof(out), &out_len);
			if (rc != E4_OK) {
				REDEBUG("rlm_eap_edhoc: message_1 processing failed: %s", edhoc4_strerror(rc));
				eap_ds->request->code = PW_EAP_FAILURE;
				return 0;
			}
		}
		if (!edhoc_queue_outgoing(eap_ds, sess, PW_EAP_REQUEST, out, out_len)) return 0;
		sess->round = 1;
		RDEBUG2("rlm_eap_edhoc: sent message_2 (%zu bytes, mode %d)", out_len, sess->mode);
		return 1;

	case 1:	/* expect message_3 -> derive MSK/EMSK */
		if (sess->mode == 3) {
			rc = edhoc03_r_handle_msg3(&sess->ctx03, msg, msg_len, out, sizeof(out), &out_len);
			if (rc != E3_OK) {
				REDEBUG("rlm_eap_edhoc: message_3 (classical) failed: %s", edhoc03_strerror(rc));
				eap_ds->request->code = PW_EAP_FAILURE;
				return 0;
			}
			if (!sess->ctx03.done) {
				REDEBUG("rlm_eap_edhoc: classical handshake not complete");
				eap_ds->request->code = PW_EAP_FAILURE;
				return 0;
			}
			/* Classical EDHOC has no message_4: succeed right after message_3. */
			eap_ds->request->code = PW_EAP_SUCCESS;
			eap_add_reply(request, "MS-MPPE-Recv-Key", sess->ctx03.msk, 32);
			eap_add_reply(request, "MS-MPPE-Send-Key", sess->ctx03.msk + 32, 32);
			RDEBUG2("rlm_eap_edhoc: classical authentication success, MSK exported");
			return 1;
		}
		rc = edhoc4_r_handle_msg3(&sess->ctx, msg, msg_len, out, sizeof(out), &out_len);
		if (rc != E4_OK) {
			REDEBUG("rlm_eap_edhoc: message_3 processing failed: %s", edhoc4_strerror(rc));
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}
		if (!edhoc_queue_outgoing(eap_ds, sess, PW_EAP_REQUEST, out, out_len)) return 0;
		sess->round = 2;
		RDEBUG2("rlm_eap_edhoc: sent message_4 (%zu bytes), handshake keys derived", out_len);
		return 1;

	case 2:	/* expect empty ACK -> EAP-Success + MPPE keys */
		if (msg_len != 0) {
			REDEBUG("rlm_eap_edhoc: expected empty ACK after message_4");
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}
		if (!sess->ctx.done) {
			REDEBUG("rlm_eap_edhoc: handshake not complete");
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}
		eap_ds->request->code = PW_EAP_SUCCESS;
		/* MSK: first 32 bytes -> Recv-Key, next 32 -> Send-Key (RFC 2548/3748) */
		eap_add_reply(request, "MS-MPPE-Recv-Key", sess->ctx.msk, 32);
		eap_add_reply(request, "MS-MPPE-Send-Key", sess->ctx.msk + 32, 32);
		RDEBUG2("rlm_eap_edhoc: authentication success, MSK exported");
		return 1;

	default:
		eap_ds->request->code = PW_EAP_FAILURE;
		return 0;
	}
}

/*
 *	The module name should be the only globally exported symbol.
 */
extern rlm_eap_module_t rlm_eap_edhoc;
rlm_eap_module_t rlm_eap_edhoc = {
	.name		= "eap_edhoc",
	.instantiate	= mod_instantiate,
	.session_init	= mod_session_init,
	.process	= mod_process,
};
