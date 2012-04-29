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

isdn_asn_interface_t g_interface;

int isdn_asn_init(isdn_asn_interface_t *interface)
{
	memcpy(&g_interface, interface, sizeof(*interface));
	return 0;
}


typedef struct asn_interface {
	isdn_asn_service_disc_e service_disc;
	isdn_asn_rose_service_id_e service_id;
	uint8_t invoke_id;
	
	asn_encoder_t encode;
} asn_interface_t;

static asn_interface_t asn_interfaces[] = {
	{ ASN_SERVICE_DISC_ROSE, ASN_ROSE_SERVICE_ID_DMS_RLT, ASN_RLT_OPERATIONIND,
		{ rlt_encode_operationid_invoke, rlt_encode_operationid_ret_result, rlt_encode_operationid_ret_error, rlt_encode_operationid_reject}},

	{ ASN_SERVICE_DISC_ROSE, ASN_ROSE_SERVICE_ID_DMS_RLT, ASN_RLT_THIRDPARTY,
 		{ rlt_encode_thirdparty_invoke, rlt_encode_thirdparty_ret_result, rlt_encode_thirdparty_ret_error, rlt_encode_thirdparty_reject}},
};


int isdn_asn_encode(isdn_asn_t *isdn_asn, uint8_t *data, uint32_t *max)
{
	int i;
	uint32_t remaining;
	service_t service;
	uint8_t *ptr = data;	
	int ret = -1;
	
	memset(&service, 0, sizeof(service));

	service.service_disc = ASN_SERVICE_DISC_ROSE;

	for (i = 0; i < isdn_asn_array_len(asn_interfaces); i++) {
		if (asn_interfaces[i].service_id == isdn_asn->service &&
			asn_interfaces[i].invoke_id == isdn_asn->invoke_id) {
			
			service.op.rose.asn_component = isdn_asn->component;
			switch (isdn_asn->component) {
				case ASN_ROSE_COMP_INVOKE:
					ret =  asn_interfaces[i].encode.invoke(isdn_asn, &service);
					break;
				case ASN_ROSE_COMP_RET_RESULT:
					ret =  asn_interfaces[i].encode.ret_result(isdn_asn, &service);
					break;
				case ASN_ROSE_COMP_RET_ERROR:
					ret =  asn_interfaces[i].encode.ret_error(isdn_asn, &service);
					break;
				case ASN_ROSE_COMP_REJECT:
					ret =  asn_interfaces[i].encode.reject(isdn_asn, &service);
					break;
			}
		}
	}

	if (ret) {
		return ret;
	}

	remaining = *max;

	/* Service discriminator */
	*ptr = ASN_SERVICE_DISC_ROSE;
	ptr++; remaining--;
	ret = asn_generate_rose(&service.op.rose, &ptr, &remaining);

	free_tags(&service.op.rose.tags);

	*max = (*max - remaining);
	return ret;
}


int isdn_asn_decode(isdn_asn_t *isdn_asn, uint8_t *data, uint32_t len)
{
	uint8_t *ptr = data;
	uint8_t service_disc = *ptr++;

	memset(isdn_asn, 0, sizeof(isdn_asn));

	switch (service_disc) {
		case ASN_SERVICE_DISC_ROSE:
			return asn_decode_rose(isdn_asn, &ptr, len - (ptr - data));
			break;
		case ASN_SERVICE_DISC_TCAP:
			/* Not supported yet */
			return -1;
			break;
	}

	return 0;
}

void free_tags(rose_tag_t **intags)
{
	rose_tag_t *tag = *intags;
	*intags = NULL;
	
	if (tag->next) {
		free_tags(&tag->next);
	}
	if (tag) {
		isdn_asn_free(tag);
	}
	return;
}

rose_tag_t *new_tag(rose_op_t *rose_op, rose_tag_e type)
{
	rose_tag_t *tags = rose_op->tags;
	rose_tag_t *tag = isdn_asn_malloc(sizeof(*tag));

	memset(tag, 0, sizeof(*tag));
	
	tag->type = type;
	
	if (!tags) {
		rose_op->tags = tag;
	} else {
		while (tags->next) {
			tags = tags->next;
		}
		tags->next = tag;
	}

	return tag;
}

uint8_t _enum2asn(enum2asn_t enum2asns[], uint32_t size, uint8_t enum_val)
{
	int i;
	for (i = 0; i < size; i++) {
		if (enum2asns[i].enum_val == enum_val) {
			return enum2asns[i].asn_val;
		}
	}
	return 0xFF;
}


uint8_t _asn2enum(enum2asn_t enum2asns[], uint32_t size, uint8_t asn_val)
{
	int i;
	for (i = 0; i < size; i++) {
		if (enum2asns[i].asn_val == asn_val) {
			return enum2asns[i].enum_val;
		}
	}
	return 0xFF;
}
