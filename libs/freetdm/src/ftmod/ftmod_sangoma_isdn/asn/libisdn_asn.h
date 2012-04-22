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

#include <stdint.h>

#ifndef __LIBISDN_ASN_H__
#define __LIBISDN_ASN_H__

struct isdn_asn_param;
typedef struct isdn_asn_param isdn_asn_param_t;

/* Service type */
typedef enum {
	ASN_SERVICE_DISC_ROSE = 0x11,
	ASN_SERVICE_DISC_TCAP = 0x12,
} isdn_asn_service_disc_e;

typedef enum {
	/* Nortel DMS related Services */
	ASN_ROSE_SERVICE_ID_DMS_RLT = 0x3E,	/* Release Link Trunk */
	ASN_ROSE_SERVICE_ID_DMS_NMS = 0x70,	/* Network Message Service */
	ASN_ROSE_SERVICE_ID_DMS_NACD = 0x7E,	/* Network Automatic Call Distribution */
	ASN_ROSE_SERVICE_ID_DMS_NRAG = 0x7F,	/* Network Ring Again */
} isdn_asn_rose_service_id_e;

typedef enum {
	ASN_RLT_OPERATIONIND = 0x01,
	ASN_RLT_THIRDPARTY = 0x02,
	ASN_RLT_NOTALLOWED = 0x03, /* TODO: Confirm value for this enum */
} isdn_asn_rlt_invoke_id_e;

/* Component Type */
typedef enum {
	ASN_ROSE_COMP_INVOKE = 0xA1,
	ASN_ROSE_COMP_RET_RESULT = 0xA2,
	ASN_ROSE_COMP_RET_ERROR = 0xA3,
	ASN_ROSE_COMP_REJECT = 0xA4,
} isdn_asn_rose_comp_e;

typedef enum {
	ASN_LOGLEVEL_DEBUG = 1,
	ASN_LOGLEVEL_ERROR,
	ASN_LOGLEVEL_CRIT,
} isdn_asn_loglevel_e;


typedef void* (*isdn_asn_malloc_func_t)(uint32_t size);
typedef char* (*isdn_asn_strdup_func_t)(char *str);
typedef void (*isdn_asn_free_func_t)(void *ptr);
typedef void (*isdn_asn_log_func_t)(uint8_t level, const char *fmt,...);

typedef struct {
	isdn_asn_malloc_func_t malloc;
	isdn_asn_strdup_func_t strdup;
	isdn_asn_free_func_t free;
	isdn_asn_log_func_t log;
} isdn_asn_interface_t;

typedef struct {
	uint32_t callid;
	uint8_t callid_len;
} rlt_operationid_retresult_params_t;

typedef struct {
	uint32_t callid;
	uint8_t callid_len;
} rlt_thirdparty_invoke_params_t;

typedef struct isdn_asn {
	isdn_asn_rose_service_id_e service;
	uint8_t invoke_id;
	isdn_asn_rose_comp_e component;

	union {
		rlt_operationid_retresult_params_t operationid_retresult;
		rlt_thirdparty_invoke_params_t thirdparty_invoke;
	} params;
} isdn_asn_t;


/* ============================= FUNCTIONS ==============================*/

int isdn_asn_init(isdn_asn_interface_t *interface);
int isdn_asn_encode(isdn_asn_t *isdn_asn, uint8_t *data, uint32_t *len);
int isdn_asn_decode(isdn_asn_t *isdn_asn, uint8_t *data, uint32_t len);

#endif /* __LIBISDN_ASN_H__ */





















