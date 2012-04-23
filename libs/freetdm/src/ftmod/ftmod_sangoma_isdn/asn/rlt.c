/*
 * Copyright (c) 2012
 * David Yat Sin <david.yatsin@gmail.com>
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



#include "libisdn_asn.h"
#include "isdn_asn.h"

#define ASN_RLT_OPERATION_INDICATION 1
#define ASN_RLT_THIRDPARTY 2

#define ASN_RLT_OPERATION_VALUE_INTEGER 0x02

#define ASN_RLT_RESULT_TAG_CALL_ID 0x80
#define ASN_RLT_REASON_FOR_REDIRECT 0x81

int rlt_encode_operationid_invoke(isdn_asn_t *isdn_asn, service_t *service)
{
	rose_tag_t *invoke_tag;
	rose_tag_t *operation_tag;	

	rose_op_t *rose_op = &service->op.rose;
	rose_op->asn_service_id = ASN_ROSE_SERVICE_ID_DMS_RLT;

	invoke_tag = new_tag(rose_op, ROSE_TAG_INVOKE);
	invoke_tag->tag.invoke.len = 1;
	invoke_tag->tag.invoke.identifier = ASN_RLT_OPERATION_INDICATION;
	
	operation_tag = new_tag(rose_op, ROSE_TAG_OPERATION);
	operation_tag->tag.operation.len = 1;
	operation_tag->tag.operation.value = ASN_RLT_OPERATION_INDICATION;
	
	return 0;
}

int rlt_encode_operationid_ret_result(isdn_asn_t *isdn_asn, service_t *service)
{
	uint32_t callid;
	rose_tag_t *invoke_tag;
	rose_tag_t *operation_tag;
	rose_tag_t *sequence_tag;
	rose_tag_t *result_tag;

	callid = isdn_asn->params.operationid_retresult.callid;

	rose_op_t *rose_op = &service->op.rose;
	rose_op->asn_service_id = ASN_ROSE_SERVICE_ID_DMS_RLT;

	invoke_tag = new_tag(rose_op, ROSE_TAG_INVOKE);
	invoke_tag->tag.invoke.len = 1;
	invoke_tag->tag.invoke.identifier = ASN_RLT_OPERATION_INDICATION;

	sequence_tag = new_tag(rose_op, ROSE_TAG_SEQUENCE);
	sequence_tag->tag.sequence.type = ROSE_SEQUENCE_TAG_SEQUENCE;
	sequence_tag->tag.sequence.len = 8; /* Sequence length is always 8 for RLT */

	operation_tag = new_tag(rose_op, ROSE_TAG_OPERATION);
	operation_tag->tag.operation.len = 1;
	operation_tag->tag.operation.value = ASN_RLT_OPERATION_INDICATION;

	result_tag = new_tag(rose_op, ROSE_TAG_RESULT);
	result_tag->tag.result.id = ASN_RLT_RESULT_TAG_CALL_ID;

	result_tag->tag.result.value[0] = (callid >> 24) & 0xFF;
	result_tag->tag.result.value[1] = (callid >> 16) & 0xFF;
	result_tag->tag.result.value[2] = (callid >> 8) & 0xFF;
	result_tag->tag.result.value[3] = callid & 0xFF;
	result_tag->tag.result.len = 3; /* Call Id Length is always 3 for RLT **weird because it is actually 4 ** */

	return 0;
}

int rlt_encode_operationid_ret_error(isdn_asn_t *isdn_asn, service_t *service)
{
	rose_tag_t *invoke_tag;
	rose_tag_t *error_tag;

	rose_op_t *rose_op = &service->op.rose;
	rose_op->asn_service_id = ASN_ROSE_SERVICE_ID_DMS_RLT;

	invoke_tag = new_tag(rose_op, ROSE_TAG_INVOKE);
	invoke_tag->tag.invoke.len = 1;
	invoke_tag->tag.invoke.identifier = ASN_RLT_OPERATION_INDICATION;
	
	error_tag = new_tag(rose_op, ROSE_TAG_ERROR);
	error_tag->tag.error.len = 1;
	error_tag->tag.error.value = isdn_asn->params.operationid_reterror.err_value;

	return 0;
}

int rlt_encode_operationid_reject(isdn_asn_t *isdn_asn, service_t *service)
{
	/* TODO: Implement me */
	return -1;
}


int rlt_encode_thirdparty_invoke(isdn_asn_t *isdn_asn, service_t *service)
{
	uint32_t callid;
	rose_tag_t *invoke_tag;
	rose_tag_t *operation_tag;
	rose_tag_t *sequence_tag;
	rose_tag_t *result_tag;
	rose_tag_t *reason_tag;

	callid = isdn_asn->params.thirdparty_invoke.callid;
	rose_op_t *rose_op = &service->op.rose;
	rose_op->asn_service_id = ASN_ROSE_SERVICE_ID_DMS_RLT;

	invoke_tag = new_tag(rose_op, ROSE_TAG_INVOKE);
	invoke_tag->tag.invoke.len = 1;
	invoke_tag->tag.invoke.identifier = ASN_RLT_THIRDPARTY;

	operation_tag = new_tag(rose_op, ROSE_TAG_OPERATION);
	operation_tag->tag.operation.len = 1;
	operation_tag->tag.operation.value = ASN_RLT_THIRDPARTY;

	sequence_tag = new_tag(rose_op, ROSE_TAG_SEQUENCE);
	sequence_tag->tag.sequence.type = ROSE_SEQUENCE_TAG_SEQUENCE;
	sequence_tag->tag.sequence.len = 8; /* Sequence length is always 8 for RLT */

	result_tag = new_tag(rose_op, ROSE_TAG_RESULT);
	result_tag->tag.result.id = ASN_RLT_RESULT_TAG_CALL_ID;

	result_tag->tag.result.value[0] = (callid >> 24) & 0xFF;
	result_tag->tag.result.value[1] = (callid >> 16) & 0xFF;
	result_tag->tag.result.value[2] = (callid >> 8) & 0xFF;
	result_tag->tag.result.value[3] = callid & 0xFF;
	
	result_tag->tag.result.len = 3; /* Call Id Length is always 3 for RLT **weird because it is actually 4 */

	reason_tag = new_tag(rose_op, ROSE_TAG_RESULT);
	reason_tag->tag.result.id = ASN_RLT_REASON_FOR_REDIRECT;

	reason_tag->tag.result.value[0] = 1; /* We don't care about this value */
	reason_tag->tag.result.len = 0; /* We will add one to the length, so set it to 0 */

	return 0;
}

int rlt_encode_thirdparty_ret_result(isdn_asn_t *isdn_asn, service_t *service)
{
	rose_tag_t *invoke_tag;

	rose_op_t *rose_op = &service->op.rose;
	rose_op->asn_service_id = ASN_ROSE_SERVICE_ID_DMS_RLT;

	invoke_tag = new_tag(rose_op, ROSE_TAG_INVOKE);
	invoke_tag->tag.invoke.len = 1;
	invoke_tag->tag.invoke.identifier = ASN_RLT_THIRDPARTY;

	return 0;
}

int rlt_encode_thirdparty_ret_error(isdn_asn_t *isdn_asn, service_t *service)
{
	return -1;
}

int rlt_encode_thirdparty_reject(isdn_asn_t *isdn_asn, service_t *service)
{
	return -1;
}


/* ===================DECODE FUNCTIONS ========================== */
int asn_decode_rlt_operationid(isdn_asn_t *isdn_asn, uint8_t **data, uint32_t len)
{
	uint8_t operation_value, operation_len, sequence_len;
	uint8_t *ptr = *data;

	switch(isdn_asn->component) {
		case ASN_ROSE_COMP_INVOKE:
			{
				/* We do not need any more info here */
				return 0;
			}
			break;
		case ASN_ROSE_COMP_RET_RESULT:
			{
				while((ptr - *data) < len) {
					switch(*ptr++) {
						case 0x30: /* Sequence Tag */
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Decoding sequence Tag\n");
							sequence_len = *ptr++;
							if (sequence_len != 0x09) {
								isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid sequence length:%d (expected:%d)\n", sequence_len, 0x09);
								return 0;
							}
							break;
						case 0x02: /* Operation Tag */
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Decoding Operation Tag\n");
							operation_len = *ptr++;
							if (operation_len != 0x01) {
								isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid operation length:%d (expected:%d)\n", sequence_len, 0x01);
								return -1;
							}
							operation_value = *ptr++;
							if (operation_value != ASN_RLT_OPERATIONIND) {
								isdn_asn_log(ASN_LOGLEVEL_ERROR, "Invalid operation value:%d (expected:%d)\n", operation_value, ASN_RLT_OPERATIONIND);
								return -1;
							}
							break;
						case 0x80: /* Call ID Tag */
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Decoding Call ID Tag\n");
							isdn_asn->params.operationid_retresult.callid_len = *ptr++;
							if (isdn_asn->params.operationid_retresult.callid_len == 0x04) {
	                                                        isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 24;
	                                                        isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 16;
	                                                        isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 8;
	                                                        isdn_asn->params.operationid_retresult.callid |= (*ptr++) ;
        	                                        } else if (isdn_asn->params.operationid_retresult.callid_len == 0x03) {
                	                                        isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 16;
                        	                                isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 8;
                                	                        isdn_asn->params.operationid_retresult.callid |= (*ptr++) ;
                                        	        } else {
                                                	        isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid call-id len value:%d\n", isdn_asn->params.operationid_retresult.callid_len);
	                                                }

							break;
						default:
							isdn_asn_log(ASN_LOGLEVEL_ERROR, "Invalid tag %x\n", *(ptr - 1));
							return -1;
							
					}
				}
			}
			break;
		case ASN_ROSE_COMP_RET_ERROR:
			isdn_asn_log(ASN_LOGLEVEL_ERROR, "Not implemented (%s:%d)\n", __FUNCTION__, __LINE__);
			break;
		case ASN_ROSE_COMP_REJECT:
			isdn_asn_log(ASN_LOGLEVEL_ERROR, "Not implemented (%s:%d)\n", __FUNCTION__, __LINE__);
			break;
		default:
			break;
	}

	return 0;
}

int asn_decode_rlt_thirdparty(isdn_asn_t *isdn_asn, uint8_t **data, uint32_t len)
{
	uint8_t operation_value, operation_len, sequence_len, reason_len, reason_value;
	uint8_t *ptr = *data;

	switch(isdn_asn->component) {
		case ASN_ROSE_COMP_INVOKE:
		{
			while((ptr - *data) < len) {
				switch(*ptr++) {
					case 0x30: /* Sequence Tag */
						isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Decoding sequence Tag\n");
						sequence_len = *ptr++;
						if (sequence_len != 0x09) {
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid sequence length:%d (expected:%d)\n", sequence_len, 0x09);
						}
						break;
					case 0x02: /* Operation Tag */
						isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Decoding Operation Tag\n");
						operation_len = *ptr++;
						if (operation_len != 0x01) {
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid sequence length:%d (expected:%d)\n", sequence_len, 0x01);
						}
						operation_value = *ptr++;
						if (operation_value != ASN_RLT_THIRDPARTY) {
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid operation value:%d (expected:%d)\n", operation_value, ASN_RLT_THIRDPARTY);
						}
						break;
					case 0x80: /* Call ID Tag */
						isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Decoding Call ID Tag\n");
						isdn_asn->params.operationid_retresult.callid_len = *ptr++;
						if (isdn_asn->params.operationid_retresult.callid_len == 0x04) {
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 24;
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 16;
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 8;
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) ;
						} else if (isdn_asn->params.operationid_retresult.callid_len == 0x03) {
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 16;
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) << 8;
							isdn_asn->params.operationid_retresult.callid |= (*ptr++) ;
						} else {
							isdn_asn_log(ASN_LOGLEVEL_DEBUG, "Invalid call-id len value:%d\n", isdn_asn->params.operationid_retresult.callid_len);
						}
						break;
					case 0x81: /* Reason for redirect */
						reason_len = *ptr++;
						if (reason_len != 0x01) {
							isdn_asn_log(ASN_LOGLEVEL_ERROR, "Invalid reason length value:%d (expected:%d)\n", reason_len, 0x01);
						}
						reason_value = *ptr++;
						break;
					default:
						isdn_asn_log(ASN_LOGLEVEL_ERROR, "Invalid tag 0x%x\n", *(ptr - 1));
						return -1;
							
				}
			}
		}
		break;
		case ASN_ROSE_COMP_RET_RESULT:
		{
			/* We do not need any more info here */
			return 0;
		}
		break;
		case ASN_ROSE_COMP_RET_ERROR:
			isdn_asn_log(ASN_LOGLEVEL_ERROR, "Not implemented (%s:%d)\n", __FUNCTION__, __LINE__);
			break;
		case ASN_ROSE_COMP_REJECT:
			isdn_asn_log(ASN_LOGLEVEL_ERROR, "Not implemented (%s:%d)\n", __FUNCTION__, __LINE__);
			break;
		default:
			break;
	}

	return 0;
}

