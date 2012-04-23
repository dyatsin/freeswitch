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


#define ASN_ROSE_TAG_INVOKE		0x02
#define ASN_ROSE_TAG_INTEGER	0x02

enum2asn_t rose_sequences [] = {
	{ ROSE_SEQUENCE_TAG_SEQUENCE,	0x30 },
	{ ROSE_SEQUENCE_TAG_SET,	0x31 },
};


int asn_generate_rose(rose_op_t *rose_op, uint8_t **buffer, uint32_t *max)
{
	uint32_t remaining;
	rose_tag_t *tag = rose_op->tags;	 
	uint8_t *ptr = (uint8_t *) *buffer;
	uint8_t *len_loc = NULL;

	remaining = *max;

	/* Service Identifier */
	*ptr = (rose_op->asn_service_id | 0x80) & 0xFF;
	ptr++; remaining--;

	/* Component type */
	*ptr = rose_op->asn_component;
	ptr++; remaining--;

	len_loc = ptr;
	ptr++; remaining--;

	while(tag) {
		switch(tag->type) {
			case ROSE_TAG_INVOKE:
				*ptr = ASN_ROSE_TAG_INVOKE;
				ptr++;
				remaining--;
				*ptr = tag->tag.invoke.len;
				ptr++;
				remaining--;
				*ptr = tag->tag.invoke.identifier;
				ptr++;
				remaining--;
				break;
			case ROSE_TAG_LINKED:
				/* TODO: Implement me */
				break;
			case ROSE_TAG_OPERATION:
				*ptr = ASN_ROSE_TAG_INTEGER;
				ptr++; remaining--;

				*ptr = tag->tag.operation.len;
				ptr++; remaining--;

				*ptr = tag->tag.operation.value;
				ptr++; remaining--;

				break;
			case ROSE_TAG_SEQUENCE:
				*ptr = enum2asn(rose_sequences, tag->tag.sequence.type);
				ptr++; remaining--;

				*ptr = tag->tag.sequence.len + 1;
				ptr++; remaining--;
	
				break;
			case ROSE_TAG_ERROR:
				*ptr = ASN_ROSE_TAG_INTEGER;
				ptr++; remaining--;

				*ptr = tag->tag.error.len;
				ptr++; remaining--;

				*ptr = tag->tag.error.value;
				ptr++; remaining--;
				
				break;
			case ROSE_TAG_PROBLEM:
				/* TODO: Implement me */
				break;
			case ROSE_TAG_ARGUMENT:
				{
					int i;
					for (i = 0; i < tag->tag.argument.len; i++) {
						*ptr = tag->tag.argument.value[i];
						ptr++;
						remaining--;
					}
				}
				break;
			case ROSE_TAG_RESULT:
				{
					int i;
					*ptr = tag->tag.result.id;
					ptr++; remaining--;

					*ptr = tag->tag.result.len + 1;
					ptr++; remaining--;

					for (i = 0; i < (tag->tag.result.len + 1); i++) {
						*ptr = tag->tag.result.value[i];
						ptr++;
						remaining--;
					}
				}
				break;
		}
		tag = tag->next;
	}
	*len_loc = ptr - len_loc - 1;

	*buffer = ptr;
	*max = remaining;
	return 0;
}

int asn_decode_rose(isdn_asn_t *isdn_asn, uint8_t **data, uint32_t len)
{
	uint8_t *ptr = *data;
	uint8_t invoke_id_tag, invoke_id_len, invoke_id_value;

	isdn_asn->service = (*ptr++) & 0x7F;
	isdn_asn->component = *ptr++;

	/* Ignore the length */
	ptr++;
	
	/* Next tag is always an invoke-id */
	invoke_id_tag = *ptr++;
	if (invoke_id_tag != 0x02) {
		isdn_asn_log(ASN_LOGLEVEL_ERROR, "Invalid Invoke ID Tag:0x%02x\n", invoke_id_tag);

	}

	invoke_id_len = *ptr++;
	if (invoke_id_len != 0x01) {
		isdn_asn_log(ASN_LOGLEVEL_ERROR, "Invalid Invoke ID Len:0x%02x\n", invoke_id_len);

	}

	invoke_id_value = *ptr++;
	isdn_asn->invoke_id = invoke_id_value;
	
	switch(isdn_asn->service) {
		case ASN_ROSE_SERVICE_ID_DMS_RLT:
			switch(invoke_id_value) {
				case ASN_RLT_OPERATIONIND:
					return asn_decode_rlt_operationid(isdn_asn, &ptr, len - (ptr-*data));
					break;
				case ASN_RLT_THIRDPARTY:
					return asn_decode_rlt_thirdparty(isdn_asn, &ptr, len - (ptr-*data));
					break;
				default:
					isdn_asn_log(ASN_LOGLEVEL_ERROR, "Unsupported Invoke ID value:0x%02x\n", invoke_id_value);
					break;
			}
			break;
		default:
			isdn_asn_log(ASN_LOGLEVEL_ERROR, "Unsupported rose service:0x%02x\n", isdn_asn->service);
			return -1;
	}

	return 0;
}

