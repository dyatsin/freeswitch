
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifndef __ISDN_ASN_H__
#define __ISDN_ASN_H__

#define isdn_asn_array_len(array) sizeof(array)/sizeof(array[0])

extern isdn_asn_interface_t g_interface;

#define isdn_asn_log(level, a,...) g_interface.log(level, a, ##__VA_ARGS__)

#define isdn_asn_malloc(size) g_interface.malloc(size)
#define isdn_asn_free(ptr) g_interface.free(ptr)
#define isdn_asn_strdup(str) g_interface.strdup(str)

struct rose_tag;
typedef struct rose_tag rose_tag_t;

typedef enum {
	ROSE_COMP_ID_INVOKE = 0x02,
	ROSE_COMP_ID_LINKED = 0x80,
	ROSE_COMP_ID_NULL = 0x05,
} rose_comp_id_e;


typedef struct {
	rose_comp_id_e id;
	uint8_t len;
} rose_invoke_id_t;

typedef struct {
	/* Not implemented */
} rose_linked_value_t;

typedef struct {
	uint8_t len;
	uint8_t value;
} rose_operation_value_t;

typedef struct {
	uint8_t len;
} rose_sequence_t;


typedef struct rose_invoke_tag {
	uint8_t len;
	uint8_t identifier;
} rose_invoke_tag_t;

typedef struct rose_linked_tag {


} rose_linked_tag_t;

typedef struct rose_operation_tag {	
	uint8_t len;
	uint8_t value;
} rose_operation_tag_t;

typedef enum {
	ROSE_SEQUENCE_TAG_SEQUENCE,
	ROSE_SEQUENCE_TAG_SET,
} rose_sequence_tag_e;

typedef struct rose_sequence_tag {
	rose_sequence_tag_e type;
	uint8_t len;
} rose_sequence_tag_t;

typedef struct rose_error_tag {


} rose_error_tag_t;

typedef struct rose_problem_tag {


} rose_problem_tag_t;

typedef struct rose_argument_tag {
	uint8_t value[10];
	uint8_t len;
} rose_argument_tag_t;

typedef struct rose_result_tag {
	uint8_t id;
	uint8_t value[10];
	uint8_t len;
} rose_result_tag_t;

typedef enum {
	ROSE_TAG_INVOKE = 1,
	ROSE_TAG_LINKED,
	ROSE_TAG_OPERATION,
	ROSE_TAG_SEQUENCE,
	ROSE_TAG_ERROR,
	ROSE_TAG_PROBLEM,
	ROSE_TAG_ARGUMENT,
	ROSE_TAG_RESULT,
} rose_tag_e;

struct rose_tag {
	rose_tag_e type;
	union {
		rose_invoke_tag_t invoke;
		rose_linked_tag_t linked;
		rose_operation_tag_t operation;
		rose_sequence_tag_t sequence;
		rose_error_tag_t error;
		rose_problem_tag_t problem;
		rose_argument_tag_t argument;
		rose_result_tag_t result;
	} tag;

	rose_tag_t *next;
};

typedef struct _rose_op {
	isdn_asn_rose_service_id_e asn_service_id; /* Service Identifier */
	
	isdn_asn_rose_comp_e asn_component;

	rose_tag_t *tags;
} rose_op_t;


typedef struct _tcap_op {
	/* Not implemented yet */
	uint8_t unused;
} tcap_op_t;


typedef struct _service {
	isdn_asn_service_disc_e service_disc;
	union {
		tcap_op_t tcap;
		rose_op_t rose;
	} op;
} service_t;

typedef int (*asn_enc_func_t) (isdn_asn_t *isdn_asn, service_t *service);

typedef struct asn_encoder {
	asn_enc_func_t invoke;
	asn_enc_func_t ret_result;
	asn_enc_func_t ret_error;
	asn_enc_func_t reject;
} asn_encoder_t;

typedef int (*asn_dec_func_t) (isdn_asn_t *isdn_asn, uint8_t **data, uint32_t *len);

typedef struct asn_decoder {
	asn_dec_func_t invoke;
	asn_dec_func_t ret_result;
	asn_dec_func_t ret_error;
	asn_dec_func_t reject;
} asn_decoder_t;

rose_tag_t *new_tag(rose_op_t *rose_op, rose_tag_e type);

typedef struct {
	uint8_t enum_val;
	uint8_t asn_val;
} enum2asn_t;

uint8_t _asn2enum(enum2asn_t enum2asns[], uint32_t size, uint8_t asn_val);
#define enum2asn(enum2asns, val) _enum2asn(enum2asns, isdn_asn_array_len(enum2asns), val)

uint8_t _enum2asn(enum2asn_t enum2asns[], uint32_t size, uint8_t enum_val);
#define asn2enum(enum2asns, val) _asn2enum(enum2asns, isdn_asn_array_len(enum2asns), val)


/* ============================= FUNCTIONS ==============================*/

int asn_decode_rlt_thirdparty(isdn_asn_t *isdn_asn, uint8_t **data, uint32_t len);
int asn_decode_rlt_operationid(isdn_asn_t *isdn_asn, uint8_t **data, uint32_t len);


int rlt_encode_operationid_invoke(isdn_asn_t *isdn_asn, service_t *service);
int rlt_encode_operationid_ret_result(isdn_asn_t *isdn_asn, service_t *service);
int rlt_encode_operationid_ret_error(isdn_asn_t *isdn_asn, service_t *service);
int rlt_encode_operationid_reject(isdn_asn_t *isdn_asn, service_t *service);

int rlt_encode_thirdparty_invoke(isdn_asn_t *isdn_asn, service_t *service);
int rlt_encode_thirdparty_ret_result(isdn_asn_t *isdn_asn, service_t *service);
int rlt_encode_thirdparty_ret_error(isdn_asn_t *isdn_asn, service_t *service);
int rlt_encode_thirdparty_reject(isdn_asn_t *isdn_asn, service_t *service);


int asn_generate_rose(rose_op_t *rose_op, uint8_t **buffer, uint32_t *max);
int asn_decode_rose(isdn_asn_t *isdn_asn, uint8_t **data, uint32_t len);


#endif /* __ISDN_ASN_H__ */








