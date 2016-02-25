/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2015 Serghei Samsi (sscdvp@gmail.com).  All rights reserved.
 */

#ifndef HASH_INTERFACE_H
#define HASH_INTERFACE_H

#include <sys/types.h>
#include <pthread.h>

/* ULONG string length constant; terminating zero is included. */
#define ULONG_STRLEN 40

#define HASH_STATUS_OK 1
#define HASH_STATUS_ERROR 2

/* 
 * Reasonable prime for different purposes.
 */
#define	GENERIC0_HASH_SIZE	503
#define	GENERIC1_HASH_SIZE	8191
#define	GENERIC2_HASH_SIZE	42589
#define	GENERIC3_HASH_SIZE	100003
#define	GENERIC4_HASH_SIZE	181081

/*
 * Key bucket.
 */
typedef struct __generic_hash_bucket generic_hash_bucket_t;
struct __generic_hash_bucket
{
	uint64_t		change;
	/* key */
	void *hb_key;					
	/* value */
	void *hb_value;					
	/* next bucket */
	generic_hash_bucket_t *hb_next;		
	/* next bucket in free buckets list */
	generic_hash_bucket_t *hb_free_next;	
	/* previous bucket in head buckets list */
	generic_hash_bucket_t *hb_head_prev;	
	/* next bucket in head buckets list */
	generic_hash_bucket_t *hb_head_next;	
	/* previous bucket in use buckets list */
	generic_hash_bucket_t *hb_use_prev;	
	/* next bucket in use buckets list */
	generic_hash_bucket_t *hb_use_next;	
	/* number of entries in head bucket */
	uint64_t hb_head_pairs;				
	/* index of head bucket in head bucket array */
	uint64_t hb_head_ind;				
};

int cmp_addr(void *,void *);
int cmp_str(void *,void *);
uint64_t hash_addr(void *);

int cmp_uint16(void *,void *);
int cmp_uint32(void *,void *);
uint64_t hash_uint16(void *);
uint64_t hash_uint32(void *);
uint64_t hash_str(void *);

uint64_t hash_buf(void *, uint32_t);

/*
 * Iterator bucket.
 */
typedef struct __generic_hash_hdl generic_hash_hdl_t;

typedef struct __generic_hash_iter generic_hash_iter_t;
struct __generic_hash_iter
{
	int				hi_run;
	/* iteration key */
	void				*hi_key;
	generic_hash_bucket_t		*hi_last_bucket;
	generic_hash_hdl_t 		*hdl;
	/* next iterator in free iterators list */
	generic_hash_iter_t	*hi_free_next;
};

/*
 * Hashing table handler.
 *	change		- detects changes to the structure
 *	lock		- mutex
 *	cmp		- comparision function
 *	hash		- hashing function
 *	buckets		- array of buckets
 *	head_buckets	- array of head buckets
 *	head_bucket_head- head of list of head buckets
 *	head_bucket_tail- tail of list of head buckets
 *	use_bucket_head - head of list of in-use buckets
 *	use_bucket_tail - tail of list of in-use buckets
 *	free_buckets	- list of unused buckets
 *	free_iterators	- list of unused iterators
 *	size		- number of buckets
 *	heads		- number of head buckets
 */
struct __generic_hash_hdl {
	uint64_t		change;
	pthread_mutex_t		lock;
	int			(*cmp)(void *,void *);
	uint64_t		(*hash)(void *);
	uint64_t		entries;
	uint64_t		size;
	uint64_t		heads;

	generic_hash_bucket_t	**buckets;
	generic_hash_bucket_t	**head_buckets;

	generic_hash_bucket_t	*head_bucket_head;
	generic_hash_bucket_t	*head_bucket_tail;
	generic_hash_bucket_t	*use_bucket_head;
	generic_hash_bucket_t	*use_bucket_tail;

	generic_hash_bucket_t	*free_buckets;
	generic_hash_iter_t	*free_iterators;
};

/*
 * Hashing functions.
 */

void
generic_hash_free(generic_hash_hdl_t **);
generic_hash_hdl_t *generic_hash_new(
	uint64_t,
	int (*cmp)(void *,void *),
	uint64_t (*hash)(void *));

uint64_t
generic_hash_length(generic_hash_hdl_t *);
void *
generic_hash_find(generic_hash_hdl_t *,void *);
void *
generic_hash_randompick(generic_hash_hdl_t *);
void *
generic_hash_add(generic_hash_hdl_t *,void *,void *);
void *
generic_hash_delete(generic_hash_hdl_t *,void *);
int generic_hash_foreach(
	generic_hash_hdl_t *,
	void (*)(void *,void **,void *),
	void *);
int generic_hash_head_foreach(
	generic_hash_hdl_t *,
	void (*)(void *,void **,void *),
	void *);

generic_hash_iter_t *
generic_hash_iter_new(generic_hash_hdl_t *,void *);
void
generic_hash_iter_free(generic_hash_iter_t **);
void *
generic_hash_iter_get_next(generic_hash_iter_t *);

#endif
