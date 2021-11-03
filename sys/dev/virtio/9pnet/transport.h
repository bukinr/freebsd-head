/*-
 * Copyright (c) 2017 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Transport definitions */
#ifndef NET_9P_TRANSPORT_H
#define NET_9P_TRANSPORT_H

/* Tranport module interface */
struct p9_trans_module {
	char *name;			/* name of transport */
	int def;			/* this transport should be default */
	/* member function to create a new conection on this transport*/
	int (*create)(struct p9_client *, const char *mount_tag);
	/* member function to terminate a connection on this transport */
	void (*close) (struct p9_client *);
	/* member function to issue a request to the transport*/
	int (*request) (struct p9_client *, struct p9_req_t *req);
	/* member function to cancel a request if it has been sent */
	int (*cancel) (struct p9_client *, struct p9_req_t *req);
	/*
	 * member function to notify that a cancelled request will not
	 * receive a reply
	 */
	int (*cancelled)(struct p9_client *, struct p9_req_t *req);
};

void p9_register_trans(struct p9_trans_module *m);
void p9_unregister_trans(struct p9_trans_module *m);
struct p9_trans_module *p9_get_trans_by_name(char *s);
struct p9_trans_module *p9_get_default_trans(void);
void p9_put_trans(struct p9_client *clnt);
void p9_init_zones(void);
void p9_destroy_zones(void);

#endif /* NET_9P_TRANSPORT_H */
