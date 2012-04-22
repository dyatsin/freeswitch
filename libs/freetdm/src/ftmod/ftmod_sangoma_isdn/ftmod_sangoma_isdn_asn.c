/*
 * Copyright (c) 2010, Sangoma Technologies 
 * David Yat Sin <davidy@sangoma.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of the original author; nor the names of any contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ftmod_sangoma_isdn.h"

void sngisdn_handle_asn(ftdm_channel_t *ftdmchan, ftdm_sngisdn_event_id_t event_id, uint8_t *data, uint32_t data_len)
{
	isdn_asn_t isdn_asn;
	sngisdn_chan_data_t *sngisdn_info = ftdmchan->call_data;
	sngisdn_span_data_t *signal_data = (sngisdn_span_data_t*) ftdmchan->span->signal_data;

	/* currently libisdn_asn only supports DMS - RLT */
	if (signal_data->switchtype != SNGISDN_SWITCH_DMS100) {
		return;
	}
	
	memset(&isdn_asn, 0, sizeof(isdn_asn));

	if (isdn_asn_decode(&isdn_asn, data, data_len)) {
		ftdm_log_chan_msg(ftdmchan, FTDM_LOG_DEBUG, "Unsupported Facility IE\n");
		return;
	}

	if (signal_data->signalling == SNGISDN_SIGNALING_NET) {
		switch (event_id) {
			case SNGISDN_EVENT_CON_IND:
				/* SETUP */
				switch(isdn_asn.service) {
					case ASN_ROSE_SERVICE_ID_DMS_RLT:
						switch(isdn_asn.component) {
							case ASN_ROSE_COMP_INVOKE:
								switch (isdn_asn.invoke_id) {
									case ASN_RLT_OPERATIONIND:
										ftdm_log_chan_msg(ftdmchan, FTDM_LOG_DEBUG, "RLT ability requested\n");
	
										sngisdn_set_flag(sngisdn_info, FLAG_RLT_OPERATIONID_INVOKE);
										sngisdn_add_var(sngisdn_info, "isdn.rlt-operation", "requested");
										break;
								}
								break;
							default:
								ftdm_log_chan(ftdmchan, FTDM_LOG_WARNING, "Unexpected rose component:%d\n", isdn_asn.component);
						} 
						break;
					default:
						ftdm_log_chan(ftdmchan, FTDM_LOG_WARNING, "Unsupported Rose service:%d\n", isdn_asn.service);
						break;
				}
	
				break;
			case SNGISDN_EVENT_FAC_IND:
				/* FACILITY */
				switch(isdn_asn.service) {
					case ASN_ROSE_SERVICE_ID_DMS_RLT:
						switch(isdn_asn.component) {
							case ASN_ROSE_COMP_INVOKE:
								switch (isdn_asn.invoke_id) {
									case ASN_RLT_THIRDPARTY:
										{
											rlt_perform_transfer(ftdmchan, isdn_asn.params.thirdparty_invoke.callid, isdn_asn.params.thirdparty_invoke.callid_len);
										}
										break;
								}
								break;
							default:
								ftdm_log_chan(ftdmchan, FTDM_LOG_WARNING, "Unexpected rose component:%d\n", isdn_asn.component);
						}
						break;
					default:
						ftdm_log_chan(ftdmchan, FTDM_LOG_WARNING, "Unsupported Rose service:%d\n", isdn_asn.service);
						break;
				}
				break;
			default:
				ftdm_log_chan(ftdmchan, FTDM_LOG_DEBUG, "Don't know how to handle ASN data from event:%d\n", event_id);
				break;
		}
	} else {
		/* Signalling = CPE */
		switch (event_id) {
			case SNGISDN_EVENT_CNST_IND:
				/* PROCEED/PROGRESS/ALERT */
				switch(isdn_asn.service) {
					case ASN_ROSE_SERVICE_ID_DMS_RLT:
						switch(isdn_asn.component) {
							case ASN_ROSE_COMP_RET_RESULT:
								switch (isdn_asn.invoke_id) {
									case ASN_RLT_OPERATIONIND:
										ftdm_log_chan(ftdmchan, FTDM_LOG_DEBUG, "RLT ability supported (call-id:0x%08x)\n", isdn_asn.params.operationid_retresult.callid);

										sngisdn_info->transfer_data.tdata.nortel_rlt.callid = isdn_asn.params.operationid_retresult.callid;
										sngisdn_info->transfer_data.tdata.nortel_rlt.callid_len = isdn_asn.params.operationid_retresult.callid_len;
	
										sngisdn_set_flag(sngisdn_info, FLAG_RLT_OPERATIONID_RESPOND);
										break;
								}
								break;
							default:
								ftdm_log_chan(ftdmchan, FTDM_LOG_WARNING, "Unexpected rose component:%d\n", isdn_asn.component);
						} 
						break;
					default:
						ftdm_log_chan(ftdmchan, FTDM_LOG_WARNING, "Unsupported Rose service:%d\n", isdn_asn.service);
						break;
				}
				break;
			default:
				ftdm_log_chan(ftdmchan, FTDM_LOG_DEBUG, "Don't know how to handle ASN data from event:%d\n", event_id);
				break;
		}
	}
	
	return;
}

void sngisdn_rltthirdparty_invoke(ftdm_channel_t *ftdmchan, uint32_t callid, uint8_t callid_len)
{
	ftdm_usrmsg_t *usrmsg;
	isdn_asn_t isdn_asn;
	uint8_t* data;
	uint32_t datalen;
	//sngisdn_chan_data_t *sngisdn_info = ftdmchan->call_data;

	datalen = 200;
	data = ftdm_malloc(datalen);
	ftdm_assert(data, "Failed to malloc");

	memset(&isdn_asn, 0, sizeof(isdn_asn));

	usrmsg = ftdm_malloc(sizeof(*usrmsg));
	
	ftdm_assert(usrmsg, "Failed to malloc");

	memset(usrmsg, 0, sizeof(*usrmsg));

	ftdm_log_chan(ftdmchan, FTDM_LOG_DEBUG, "RLT transfer requested (call-id:0x%08x)\n", callid);
	
	isdn_asn.service = ASN_ROSE_SERVICE_ID_DMS_RLT;
	isdn_asn.invoke_id = ASN_RLT_THIRDPARTY;
	isdn_asn.component = ASN_ROSE_COMP_INVOKE;
	isdn_asn.params.thirdparty_invoke.callid = callid;
	isdn_asn.params.thirdparty_invoke.callid_len = callid_len;
	
	if (isdn_asn_encode(&isdn_asn, &data[2], &datalen)) {
		ftdm_log_chan_msg(ftdmchan, FTDM_LOG_ERROR, "Failed to encode return result\n");
		return;
	}

	data[0] = SNGISDN_Q931_FACILITY_IE_ID;
	data[1] = datalen;

	ftdm_usrmsg_set_raw_data(usrmsg, data, datalen);

	ftdmchan->usrmsg = usrmsg;
}

void sngisdn_rltthirdparty_respond(ftdm_channel_t *ftdmchan)
{
	ftdm_usrmsg_t *usrmsg;
	isdn_asn_t isdn_asn;
	uint8_t* data;
	uint32_t datalen;

	datalen = 200;
	data = ftdm_malloc(datalen);
	ftdm_assert(data, "Failed to malloc");

	memset(&isdn_asn, 0, sizeof(isdn_asn));

	usrmsg = ftdm_malloc(sizeof(*usrmsg));
	
	ftdm_assert(usrmsg, "Failed to malloc");

	memset(usrmsg, 0, sizeof(*usrmsg));
	
	/* DAVIDY TODO: handle case where we fail!! */

	isdn_asn.service = ASN_ROSE_SERVICE_ID_DMS_RLT;
	isdn_asn.invoke_id = ASN_RLT_THIRDPARTY;
	isdn_asn.component = ASN_ROSE_COMP_RET_RESULT;
	
	if (isdn_asn_encode(&isdn_asn, &data[2], &datalen)) {
		ftdm_log_chan_msg(ftdmchan, FTDM_LOG_ERROR, "Failed to encode return result\n");
		return;
	}

	data[0] = SNGISDN_Q931_FACILITY_IE_ID;
	data[1] = datalen;

	ftdm_usrmsg_set_raw_data(usrmsg, data, datalen);

	ftdmchan->usrmsg = usrmsg;
}

void sngisdn_rltoperationid_invoke(ftdm_channel_t *ftdmchan)
{
	isdn_asn_t isdn_asn;
	uint8_t* data;
	uint32_t datalen;
	sngisdn_chan_data_t *sngisdn_info = ftdmchan->call_data;

	sngisdn_set_flag(sngisdn_info, FLAG_RLT_OPERATIONID_INVOKE);

	datalen = 200;
	data = ftdm_malloc(datalen);

	memset(&isdn_asn, 0, sizeof(isdn_asn));

	isdn_asn.service = ASN_ROSE_SERVICE_ID_DMS_RLT;
	isdn_asn.invoke_id = ASN_RLT_OPERATIONIND;
	isdn_asn.component = ASN_ROSE_COMP_INVOKE;

	if (isdn_asn_encode(&isdn_asn, &data[2], &datalen)) {
		ftdm_log_chan_msg(ftdmchan, FTDM_LOG_ERROR, "Failed to encode return result\n");
		return;
	}

	data[0] = SNGISDN_Q931_FACILITY_IE_ID;
	data[1] = datalen;
	
	ftdm_usrmsg_set_raw_data(ftdmchan->usrmsg, data, datalen);
	return;
}


void sngisdn_rltoperationid_respond(ftdm_channel_t *ftdmchan)
{
	isdn_asn_t isdn_asn;
	uint8_t* data;
	uint32_t datalen;	
	const char *var = NULL;
	sngisdn_chan_data_t *sngisdn_info = ftdmchan->call_data;

	sngisdn_set_flag(sngisdn_info, FLAG_RLT_OPERATIONID_RESPOND);

	datalen = 200;
	data = ftdm_malloc(datalen);

	memset(&isdn_asn, 0, sizeof(isdn_asn));

	var = ftdm_usrmsg_get_var(ftdmchan->usrmsg, "isdn.rlt-operation");
	if (!ftdm_strlen_zero(var) && !strncasecmp(var, "allowed", strlen("allowed"))) {
		isdn_asn.service = ASN_ROSE_SERVICE_ID_DMS_RLT;
		isdn_asn.invoke_id = ASN_RLT_OPERATIONIND;
		isdn_asn.component = ASN_ROSE_COMP_RET_RESULT;

#ifndef WIN32
		isdn_asn.params.operationid_retresult.callid = (uint32_t)(random() & 0xffffffff);
#else
		isdn_asn.params.operationid_retresult.callid = (uint32_t)(rand() & 0xffffffff);
#endif
		isdn_asn.params.operationid_retresult.callid_len = 4;
				
		sngisdn_info->transfer_data.tdata.nortel_rlt.callid = isdn_asn.params.operationid_retresult.callid;
		sngisdn_info->transfer_data.tdata.nortel_rlt.callid_len = 4;

		ftdm_log_chan(ftdmchan, FTDM_LOG_DEBUG, "RLT ability allowed (call-id:0x%08x)\n", isdn_asn.params.operationid_retresult.callid);
	} else {
		isdn_asn.service = ASN_ROSE_SERVICE_ID_DMS_RLT;
		isdn_asn.invoke_id = ASN_RLT_NOTALLOWED;
		isdn_asn.component = ASN_ROSE_COMP_RET_RESULT;
	}

	if (isdn_asn_encode(&isdn_asn, &data[2], &datalen)) {
		ftdm_log_chan_msg(ftdmchan, FTDM_LOG_ERROR, "Failed to encode return result\n");
		return;
	}

	data[0] = SNGISDN_Q931_FACILITY_IE_ID;
	data[1] = datalen;
	
	ftdm_usrmsg_set_raw_data(ftdmchan->usrmsg, data, datalen);
}
