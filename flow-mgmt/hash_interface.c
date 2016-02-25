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
 * Copyright 1991 fnv-mail@asthe.com
 * Copyright 2015 Serghei Samsi (sscdvp@gmail.com).  All rights reserved.
 */
/*
 * This file contains re-used FNV hashing implementation.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "hash_interface.h"

/*
 * GENERIC_HASH_64_INIT is the same as the INIT value since it is the value
 * used by FNV (FNV1_64_INIT). More details on FNV are available at:
 *
 * http://www.isthe.com/chongo/tech/comp/fnv/index.html
 */
#define	GENERIC_HASH_64_INIT	(0xcbf29ce484222325ULL) /* Hash initializer */

/*
 * GENERIC_HASH_64_PRIME is a large prime number chosen to minimize hashing
 * collisions.
 */
#define	GENERIC_HASH_64_PRIME	(0x100000001b3ULL)	/* Large Prime */

/*
 * GENERIC_HASH_SIZE is chosen as it is the nearest prime to 2^13 (8192).
 * 8192 is chosen as it is unlikely that this hash table will contain more
 * elements than this in normal operation. Of course overflow in each
 * bucket is acceptable, but if there is too much overflow, then
 * performance will degrade to that of a list.
 */
#define	GENERIC_HASH_SIZE	8191			/* Reasonable prime */

/*
 * Default functions for hashing and comparing if the user does not specify
 * these values when creating the handle.
 */
int		cmp_addr(void *, void *);
int		cmp_uint32(void *, void *);
uint64_t	hash_addr(void *);
uint64_t	hash_buf(void *, uint32_t);

/*
 * Default comparison function which is used if no comparison function
 * is supplied when the handle is created. The default behaviour
 * is to compare memory address.
 */
int
cmp_addr(void *x, void *y)
{
	return (x != y);
}

int
cmp_uint16(void *x, void *y)
{
	uint16_t *x1 = (uint16_t *)x;
	uint16_t *y1 = (uint16_t *)y;
	return (*x1 != *y1);
}

int
cmp_uint32(void *x, void *y)
{
	uint32_t *x1 = (uint32_t *)x;
	uint32_t *y1 = (uint32_t *)y;
	return (*x1 != *y1);
}

int
cmp_str(void *x, void *y)
{
	return (strcmp(x, y) != 0);
}

/*
 * The default hashing function which is used if no hashing function
 * is provided when the handle is created. The default behaviour
 * is to use the hash_buf() function.
 */
uint64_t
hash_addr(void *key)
{
	return (hash_buf(&key, sizeof (key)));
}

uint64_t
hash_uint16(void *key)
{
	char keystring[ULONG_STRLEN];
	uint16_t *vkey = (uint16_t *)key;
	char *start = &keystring[0];
	char *end = start;
	uint64_t hash = GENERIC_HASH_64_INIT;
	bzero(&keystring, ULONG_STRLEN);
	strlcat(&keystring[0],
	    ulltostr(*vkey,
		&keystring[ULONG_STRLEN - 1]),
		ULONG_STRLEN);
	end = start + strlen(keystring);

	while (start < end) {
		hash *= GENERIC_HASH_64_PRIME;
		hash ^= (uint64_t)*start++;
	}

	return (hash);
}

uint64_t
hash_uint32(void *key)
{
	char keystring[ULONG_STRLEN];
	uint32_t *vkey = (uint32_t *)key;
	char *start = &keystring[0];
	char *end = start;
	uint64_t hash = GENERIC_HASH_64_INIT;
	bzero(&keystring, ULONG_STRLEN);
	strlcat(&keystring[0],
	    ulltostr(*vkey,
		&keystring[ULONG_STRLEN - 1]),
		ULONG_STRLEN);
	end = start + strlen(keystring);

	while (start < end) {
		hash *= GENERIC_HASH_64_PRIME;
		hash ^= (uint64_t)*start++;
	}

	return (hash);
}

/*
 * Return a hash which is built by manipulating each byte in the
 * supplied data. The hash logic follows the approach suggested in the
 * FNV hash.
 */
uint64_t
hash_buf(void *buf, uint32_t len)
{
	char *start = (char *)buf;
	char *end = start + len;
	uint64_t hash = GENERIC_HASH_64_INIT;

	while (start < end) {
		hash *= GENERIC_HASH_64_PRIME;
		hash ^= (uint64_t)*start++;
	}

	return (hash);
}

/*
 * Return a hash which is built by manipulating each byte in the
 * supplied string. The hash logic follows the approach suggested in
 * the FNV hash.
 */
uint64_t
hash_str(void *str)
{
	unsigned char *p = (unsigned char *)str;
	uint64_t hash = GENERIC_HASH_64_INIT;

	while (*p) {
		hash *= GENERIC_HASH_64_PRIME;
		hash ^= (uint64_t)*p++;
	}

	return (hash);
}

/* Maintain head buckets list */
void
generic_hash_head_list_remove(
	generic_hash_hdl_t *hdl,
	generic_hash_bucket_t *bucket)
{
	generic_hash_bucket_t *prev_bucket;

	if (bucket == NULL)
		return;

	prev_bucket = bucket->hb_head_prev;
	if (prev_bucket != NULL) {
		if (bucket->hb_head_next != NULL) {
			prev_bucket->hb_head_next =
			    bucket->hb_head_next;
			bucket->hb_head_next = NULL;
			prev_bucket->hb_head_next->hb_head_prev =
			    prev_bucket;
		} else {
			hdl->head_bucket_tail =
			    prev_bucket;
			prev_bucket->hb_head_next = NULL;
		}
		bucket->hb_head_prev = NULL;
	} else if (bucket->hb_head_next != NULL) {
		hdl->head_bucket_head =
		    bucket->hb_head_next;
		bucket->hb_head_next = NULL;
		hdl->head_bucket_head -> hb_head_prev =
		    NULL;
	} else {
		hdl->head_bucket_head = NULL;
		hdl->head_bucket_tail = NULL;
	}
}

void
generic_hash_head_list_add(
	generic_hash_hdl_t *hdl,
	generic_hash_bucket_t *bucket)
{
	if (bucket == NULL)
		return;

	if (hdl->head_bucket_tail == NULL) {
		hdl->head_bucket_head =
		hdl->head_bucket_tail =
		    bucket;
	} else {
		hdl->head_bucket_tail->hb_head_next =
		    bucket;
		bucket->hb_head_prev = hdl->head_bucket_tail;
		hdl->head_bucket_tail = bucket;
	}
}

/* Maintain in-use buckets list */
void
generic_hash_use_list_remove(
	generic_hash_hdl_t *hdl,
	generic_hash_bucket_t *bucket)
{
	generic_hash_bucket_t *prev_bucket;

	if (bucket == NULL)
		return;

	prev_bucket = bucket->hb_use_prev;
	if (prev_bucket != NULL) {
		if (bucket->hb_use_next != NULL) {
			prev_bucket->hb_use_next =
			    bucket->hb_use_next;
			bucket->hb_use_next = NULL;
			prev_bucket->hb_use_next->hb_use_prev =
			    prev_bucket;
		} else {
			hdl->use_bucket_tail =
			    prev_bucket;
			prev_bucket->hb_use_next = NULL;
		}
		bucket->hb_use_prev = NULL;
	} else if (bucket->hb_use_next != NULL) {
		hdl->use_bucket_head =
		    bucket->hb_use_next;
		bucket->hb_use_next = NULL;
		hdl->use_bucket_head -> hb_use_prev =
		    NULL;
	} else {
		hdl->use_bucket_head = NULL;
		hdl->use_bucket_tail = NULL;
	}
}

void
generic_hash_use_list_add(
	generic_hash_hdl_t *hdl,
	generic_hash_bucket_t *bucket)
{
	if (bucket == NULL)
		return;

	if (hdl->use_bucket_tail == NULL) {
		hdl->use_bucket_head =
		hdl->use_bucket_tail =
		    bucket;
	} else {
		hdl->use_bucket_tail->hb_use_next =
		    bucket;
		bucket->hb_use_prev = hdl->use_bucket_tail;
		hdl->use_bucket_tail = bucket;
	}
}

/*
 * public interface
 */

int get_random(int start, int end)
{
	return (start + (int) (end * 1.0 * (rand() / (RAND_MAX + start * 1.0))));
}

/*
 * Create a new iterator for hash table.
 */
generic_hash_iter_t *
generic_hash_iter_new(generic_hash_hdl_t *hdl, void *key)
{
	generic_hash_iter_t *iter;

	if ((hdl == NULL) || (key == NULL))
		return (NULL);

	iter = hdl->free_iterators;
	if (iter == NULL) {
/*		iter = (generic_hash_iter_t *)alloc_dyn(sizeof (generic_hash_iter_t));*/
		iter = (generic_hash_iter_t *)calloc(1, sizeof (generic_hash_iter_t));
		if (iter == NULL)
			return (NULL);
/*		bzero(iter, sizeof (generic_hash_iter_t));*/
		iter->hdl = hdl;
	} else {
		hdl->free_iterators = iter->hi_free_next;
	}
	iter->hi_free_next = NULL;
	iter->hi_last_bucket = NULL;
	iter->hi_key = key;
	iter->hi_run = 0;

	return (iter);
}

/*
 * Free iterator resources for supplied iterator.
 */
void
generic_hash_iter_free(generic_hash_iter_t **iter)
{
	if ((iter == NULL) || (*iter == NULL) || ((*iter)->hdl == NULL))
		return;
	(*iter)->hi_key = NULL;
	(*iter)->hi_last_bucket = NULL;
	(*iter)->hi_run = 0;
	(*iter)->hi_free_next = (*iter)->hdl->free_iterators;
	(*iter)->hdl->free_iterators = (*iter);
	*iter = NULL;
}

/*
 * Find a value for next available member of hash bucket list (iterator mode).
 * NULL is returned if the key cannot be
 * found.
 */
void *
generic_hash_iter_get_next(generic_hash_iter_t *iter)
{
	generic_hash_bucket_t *bucket;
	void *value;

	if ((iter == NULL) || (iter->hdl == NULL) || (iter->hi_key == NULL))
		return (NULL);
	if (iter->hi_run == 0) {
		uint64_t hi_index = (*iter->hdl->hash)(iter->hi_key) % iter->hdl->size;
		iter->hi_last_bucket = iter->hdl->buckets[hi_index];
		iter->hi_run = 1;
	}

	for (bucket = iter->hi_last_bucket; bucket != NULL;
	    bucket = bucket->hb_next)
		if ((*iter->hdl->cmp)(iter->hi_key, bucket->hb_key) == 0)
			break;
	if (bucket == NULL)
		return (NULL);
	value = bucket->hb_value;
	bucket = bucket->hb_next;
	iter->hi_last_bucket = bucket;

	return (value);
}

/*
 * Return the number of keys held in the supplied handle.
 */
uint64_t
generic_hash_length(generic_hash_hdl_t *hdl)
{
	if (hdl == NULL)
		return (0);

	return (hdl->entries);
}

/*
 * Free the supplied handle and all it's associated resource.
 */
void
generic_hash_free(generic_hash_hdl_t **hdl)
{
	generic_hash_bucket_t *bucket, *next_bucket;
	generic_hash_iter_t *iter, *next_iter;
/*	uint64_t i;*/

	if ((hdl == NULL) || (*hdl == NULL))
		return;

	pthread_mutex_lock(&(*hdl)->lock);
/*	if ((*hdl)->heads > 0) {
		for (i = 0; i < (*hdl)->heads; i++) {
			for (bucket = (*hdl)->head_buckets[i]; bucket != NULL;
			    bucket = next_bucket) {
				next_bucket = bucket->hb_next;
				bucket->hb_free_next = (*hdl)->free_buckets;
				(*hdl)->free_buckets = bucket;
			}
		}
	}*/
	if ((*hdl)->use_bucket_head != NULL) {
		bucket = (*hdl)->use_bucket_head;
		while (bucket != NULL) {
			next_bucket = bucket->hb_use_next;
			generic_hash_use_list_remove(*hdl, bucket);
			bucket->hb_free_next = (*hdl)->free_buckets;
			(*hdl)->free_buckets = bucket;
			bucket = next_bucket;
		}
	}
	if ((*hdl)->free_buckets != NULL) {
		bucket = (*hdl)->free_buckets;
		while (bucket != NULL) {
			next_bucket = bucket->hb_free_next;
			free(bucket);
/*			alloc_free(bucket);*/
			bucket = next_bucket;
		}
	}
	if ((*hdl)->buckets != NULL)
		free((*hdl)->buckets);
/*		alloc_free((*hdl)->buckets);*/
	if ((*hdl)->head_buckets != NULL)
		free((*hdl)->head_buckets);
/*		alloc_free((*hdl)->head_buckets);*/
	if ((*hdl)->free_iterators != NULL) {
		iter = (*hdl)->free_iterators;
		next_iter = NULL;
		while (iter != NULL) {
			next_iter = iter->hi_free_next;
			free(iter);
/*			alloc_free(iter);*/
			iter = next_iter;
		}
	}
	pthread_mutex_unlock(&(*hdl)->lock);
	pthread_mutex_destroy(&(*hdl)->lock);
	free((*hdl));
/*	alloc_free((*hdl));*/
	*hdl = NULL;
}

/*
 * Create a new hash table handle using the supplied comparison and helper
 * hashing routines. If none of them is supplied then the defaults are used.
 */
generic_hash_hdl_t *
generic_hash_new(uint64_t ht_size, int (*cmp)(void *, void *), 
    uint64_t (*hash)(void *))
{
	generic_hash_hdl_t *hdl;
	generic_hash_bucket_t *bucket, *prev_bucket;
	uint64_t i;

	if ((hdl = calloc(1, sizeof (generic_hash_hdl_t))) == NULL) {
/*	if ((hdl = (generic_hash_hdl_t *)alloc_dyn(sizeof (generic_hash_hdl_t))) == NULL) {*/
		return (NULL);
	}
/*	bzero(hdl, sizeof (generic_hash_hdl_t));*/
	hdl->change = 0;
	hdl->heads = 0;
	hdl->entries = 0;
	pthread_mutex_init(&hdl->lock, NULL);
	pthread_mutex_lock(&hdl->lock);
	hdl->cmp = cmp ? cmp : cmp_addr;
	hdl->hash = hash ? hash : hash_addr;
	hdl->free_iterators = NULL;
	hdl->free_buckets = NULL;
	hdl->head_buckets = NULL;

	hdl->head_bucket_head = NULL;
	hdl->head_bucket_tail = NULL;

	hdl->use_bucket_head = NULL;
	hdl->use_bucket_tail = NULL;

	if (ht_size == 0)
	    hdl->size = GENERIC_HASH_SIZE;
	else
	    hdl->size = ht_size;
	if ((hdl->buckets = calloc(hdl->size, sizeof (generic_hash_bucket_t *))) == NULL) {
/*	if ((hdl->buckets = (generic_hash_bucket_t **)alloc_dyn(hdl->size * sizeof (generic_hash_bucket_t *))) == NULL) {*/
		free(hdl);
/*		alloc_free(hdl);*/
		pthread_mutex_unlock(&hdl->lock);
		return (NULL);
	}
	if ((hdl->head_buckets = (generic_hash_bucket_t **)calloc(hdl->size, sizeof (generic_hash_bucket_t *))) == NULL) {
/*	if ((hdl->head_buckets = (generic_hash_bucket_t **)alloc_dyn(hdl->size * sizeof (generic_hash_bucket_t *))) == NULL) {*/
		pthread_mutex_unlock(&hdl->lock);
		generic_hash_free(&hdl);
		return (NULL);
	}
	for (i = 0; i < hdl->size; i++) {
		hdl->buckets[i] = NULL;
		hdl->head_buckets[i] = NULL;
	}

	prev_bucket = NULL;
	for (i = 0; i < hdl->size; i++) {
		bucket = malloc(sizeof (generic_hash_bucket_t));
/*		bucket = (generic_hash_bucket_t *)alloc_dyn(sizeof (generic_hash_bucket_t));*/
		if (bucket == NULL) {
			pthread_mutex_unlock(&hdl->lock);
			generic_hash_free(&hdl);
			return (NULL);
		}
		bzero(bucket, sizeof (generic_hash_bucket_t));
/*		memset(bucket, 0, sizeof (generic_hash_bucket_t));*/
		bucket->hb_key = NULL;
		bucket->hb_value = NULL;
		bucket->hb_next = NULL;
		bucket->hb_free_next = NULL;
		bucket->hb_head_pairs = 0;
		bucket->hb_head_ind = 0;

		bucket->hb_head_next = NULL;
		bucket->hb_head_prev = NULL;

		bucket->hb_use_next = NULL;
		bucket->hb_use_prev = NULL;

		if (i == 0) {
			hdl->free_buckets = bucket;
		} else {
			prev_bucket->hb_free_next = bucket;
		}
		prev_bucket = bucket;
	}
	pthread_mutex_unlock(&hdl->lock);
	return (hdl);
}

/*
 * Find a value from the hash. NULL is returned if the key cannot be
 * found.
 */
void *
generic_hash_find(generic_hash_hdl_t *hdl, void *key)
{
	uint64_t i;
	generic_hash_bucket_t *bucket;

	if ((hdl == NULL) || (key == NULL))
		return (NULL);

	pthread_mutex_lock(&hdl->lock);
	i = (*hdl->hash)(key) % hdl->size;
	for (bucket = hdl->buckets[i]; bucket != NULL;
	    bucket = bucket->hb_next)
		if ((*hdl->cmp)(key, bucket->hb_key) == 0)
			break;
	pthread_mutex_unlock(&hdl->lock);
	return (bucket ? bucket->hb_value : NULL);
}

/*
 * Pick a random value from the hash. NULL is returned in the cases if the hash table
 * has no member or if empty bucket key.
 */
void *
generic_hash_randompick(generic_hash_hdl_t *hdl)
{
	uint64_t ir, j, jr;
	generic_hash_bucket_t *bucket, *hbucket;

	if ((hdl == NULL) || (hdl->heads == 0))
		return (NULL);

	pthread_mutex_lock(&hdl->lock);
	if (hdl->heads > 0) {
    	    ir = get_random(1, hdl->heads);
	    if (ir > 0) ir--;
	} else {
	    ir = 0;
	}
        hbucket = hdl->head_buckets[ir];
	if (hbucket == NULL) {
		pthread_mutex_unlock(&hdl->lock);
		return (NULL);
	}
	if (hbucket->hb_head_pairs > 0)
		jr = get_random(1, hbucket->hb_head_pairs);
	else
		jr = 1;
	j = 0;
	for (bucket = hbucket; bucket != NULL;
	    bucket = bucket->hb_next) {
		if ((bucket->hb_key != NULL) && (++j == jr))
			break;
	}
	pthread_mutex_unlock(&hdl->lock);
	return (bucket ? bucket->hb_value : NULL);
}

/*
 * Put an entry into the hash. NULL is returned if bucket couldn't be allocated,
 * new value is retuned if this key was not
 * already present, otherwise the previous value is returned.
 */
void *
generic_hash_add(generic_hash_hdl_t *hdl, void *key, void *value)
{
	uint64_t i, last_hbucket_ind;
	generic_hash_bucket_t *bucket;
	void *last_value = NULL;

	if ((hdl == NULL) || (key == NULL) || (value == NULL))
		return (NULL);

	pthread_mutex_lock(&hdl->lock);
	i = (*hdl->hash)(key) % hdl->size;
	for (bucket = hdl->buckets[i]; bucket != NULL;
	    bucket = bucket->hb_next)
		if ((*hdl->cmp)(key, bucket->hb_key) == 0)
			break;
	if (bucket) {
		last_value = bucket->hb_value;
	} else {
		if (hdl->free_buckets != NULL) {
			bucket = hdl->free_buckets;
			hdl->free_buckets = bucket->hb_free_next;
		} else {
			bucket = malloc(sizeof (generic_hash_bucket_t));
/*			bucket = (generic_hash_bucket_t *)alloc_dyn(sizeof (generic_hash_bucket_t));*/
			if (bucket == NULL) {
				pthread_mutex_unlock(&hdl->lock);
				return (NULL);
			}
			bzero(bucket, sizeof (generic_hash_bucket_t));
			/*memset(bucket, 0, sizeof (generic_hash_bucket_t));*/
		}
		bucket->hb_key = key;
		bucket->hb_free_next = NULL;
		bucket->hb_head_pairs = 0;
		bucket->hb_head_ind = 0;

		bucket->hb_head_next = NULL;
		bucket->hb_head_prev = NULL;

		bucket->hb_use_next = NULL;
		bucket->hb_use_prev = NULL;

		if (hdl->buckets[i] != NULL) {
			generic_hash_head_list_remove(hdl, hdl->buckets[i]);

			bucket->hb_head_pairs = hdl->buckets[i]->hb_head_pairs;
			hdl->buckets[i]->hb_head_pairs = 0;

			last_hbucket_ind = hdl->buckets[i]->hb_head_ind;
			hdl->buckets[i]->hb_head_ind = 0;

			hdl->head_buckets[last_hbucket_ind] = bucket;
			bucket->hb_head_ind = last_hbucket_ind;
		} else {
			hdl->head_buckets[hdl->heads] = bucket;
			bucket->hb_head_ind = hdl->heads;
			hdl->heads++;
		}
		bucket->hb_head_pairs++;

		bucket->hb_next = hdl->buckets[i];
		hdl->buckets[i] = bucket;

		generic_hash_head_list_add(hdl, bucket);
		generic_hash_use_list_add(hdl, bucket);

		hdl->entries++;
		last_value = value;
	}

	hdl->change++;
	bucket->change = hdl->change;

	bucket->hb_value = value;
	pthread_mutex_unlock(&hdl->lock);
	return (last_value);
}

/*
 * Remove the key/value from the handle. The value is returned if
 * the key is found. NULL is returned if the key cannot be located.
 */
void *
generic_hash_delete(generic_hash_hdl_t *hdl, void *key)
{
	uint64_t i;
	void *value;
	generic_hash_bucket_t *bucket, *prev_bucket, **pbucket;

	if ((hdl == NULL) || (key == NULL))
		return (NULL);

	pthread_mutex_lock(&hdl->lock);
	i = (*hdl->hash)(key) % hdl->size;

	prev_bucket = NULL;
	for (pbucket = &hdl->buckets[i]; *pbucket != NULL;
	    pbucket = &(*pbucket)->hb_next) {
		if ((*hdl->cmp)(key, (*pbucket)->hb_key) == 0) {
			bucket = *pbucket;

			generic_hash_use_list_remove(hdl, bucket);

			if (prev_bucket == NULL) {
				generic_hash_head_list_remove(hdl, bucket);

				hdl->buckets[i] = bucket->hb_next;
				if (hdl->buckets[i] != NULL) {
					generic_hash_head_list_add(hdl, hdl->buckets[i]);

					hdl->buckets[i]->hb_head_pairs = bucket->hb_head_pairs;

					hdl->head_buckets[bucket->hb_head_ind] = hdl->buckets[i];
					hdl->buckets[i]->hb_head_ind = bucket->hb_head_ind;
				} else {
					if (hdl->heads > 0)
						hdl->heads--;
					hdl->head_buckets[bucket->hb_head_ind] = hdl->head_buckets[hdl->heads];
					hdl->head_buckets[hdl->heads] = NULL;
					if (hdl->head_buckets[bucket->hb_head_ind] != NULL)
						hdl->head_buckets[bucket->hb_head_ind]->hb_head_ind = bucket->hb_head_ind;
				}

			} else {
				prev_bucket->hb_next = bucket->hb_next;
			}
			bucket->hb_next = NULL;

/*			free(bucket);*/
			bucket->hb_free_next = hdl->free_buckets;
			hdl->free_buckets = bucket;

			bucket->hb_head_pairs = 0;
			bucket->hb_head_ind = 0;
			bucket->hb_key = NULL;
			value = bucket->hb_value;
			bucket->hb_value = NULL;

			if (hdl->entries > 0)
				hdl->entries--;
			if ((hdl->buckets[i] != NULL) &&
			     (hdl->buckets[i]->hb_head_pairs > 0))
				hdl->buckets[i]->hb_head_pairs--;

			hdl->change++;
			bucket->change = hdl->change;

			pthread_mutex_unlock(&hdl->lock);
			return (value);
		}
		prev_bucket = *pbucket;
	}
	pthread_mutex_unlock(&hdl->lock);
	return (NULL);
}

/*
void
generic_hash_foreach(generic_hash_hdl_t *hdl, void (*func_task)(void *, void **, void *),
    void *cl)
{
	uint64_t i;
	generic_hash_bucket_t *bucket = NULL, *next_bucket;
	uint64_t change_stamp;

	if (hdl == NULL)
		return;

	pthread_mutex_lock(&hdl->lock);
	change_stamp = hdl->change;
	for (i = 0; i < hdl->size; i++) {
		for (bucket = hdl->buckets[i]; bucket != NULL;
		    bucket = next_bucket) {
			next_bucket = bucket->hb_next;
			pthread_mutex_unlock(&hdl->lock);
			func_task(bucket->hb_key, &bucket->hb_value, cl);
			pthread_mutex_lock(&hdl->lock);
			if (hdl->change != change_stamp &&
			    hdl->change != bucket->change)
				goto done;
		}
	}
done:
	pthread_mutex_unlock(&hdl->lock);
}
*/
/*
 * For all entries in the handle call the user supplied function
 * (func_task) with the key, value and user supplied data.
 */
int
generic_hash_foreach(
    generic_hash_hdl_t *hdl,
    void (*func_task)(void *, void **, void *),
    void *cl)
{
	generic_hash_bucket_t *bucket = NULL, *next_bucket;
	uint64_t change_stamp;
	int status = HASH_STATUS_ERROR;

	if (hdl == NULL)
		return (status);

	pthread_mutex_lock(&hdl->lock);
	change_stamp = hdl->change;
	for (bucket = hdl->use_bucket_head;
	    bucket != NULL; bucket = next_bucket) {
		next_bucket = bucket->hb_use_next;
		pthread_mutex_unlock(&hdl->lock);
		func_task(bucket->hb_key, &bucket->hb_value, cl);
		pthread_mutex_lock(&hdl->lock);
		/* We should test change,
		 * if we're deleting some hash entries.
		 * We agree func_task() could touch
		 * bucket pointer only.
		 */
		if (hdl->change != change_stamp &&
		    hdl->change != bucket->change)
			goto done;
		change_stamp = hdl->change;
	}
	status = HASH_STATUS_OK;
done:
	pthread_mutex_unlock(&hdl->lock);
	return (status);
}

/* ARGUSED */
int
generic_hash_head_foreach(
    generic_hash_hdl_t *hdl,
    void (*func_task)(void *, void **, void *),
    void *cl)
{
	generic_hash_bucket_t *bucket = NULL, *next_bucket;
	uint64_t change_stamp;
	int status = HASH_STATUS_ERROR;

	if (hdl == NULL)
		return (status);

	pthread_mutex_lock(&hdl->lock);
	change_stamp = hdl->change;
	for (bucket = hdl->head_bucket_head;
	    bucket != NULL; bucket = next_bucket) {
		next_bucket = bucket->hb_head_next;
		pthread_mutex_unlock(&hdl->lock);
		func_task(bucket->hb_key, &bucket->hb_value, cl);
		pthread_mutex_lock(&hdl->lock);
		if (hdl->change != change_stamp &&
		    hdl->change != bucket->change)
			goto done;
		change_stamp = hdl->change;
	}
	status = HASH_STATUS_OK;
done:
	pthread_mutex_unlock(&hdl->lock);
	return (status);
}
