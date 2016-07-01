/*
 * Copyright (c) CoCo Communications, 2015
 *
 *  Copyright holder grants permission for redistribution and use in source
 *  and binary forms, with or without modification, provided that the
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *     3. All advertising materials and documentation mentioning features
 *	  or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Jesse Jones (jjones at cococorp dot com)"
 *
 *  "DISCLAIMER OF LIABILITY
 *
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */
#include "watch_ips.h"

#include "common.h"
#include "rekey.h"
#include <errno.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
#include <unistd.h>

static void* monitor_addresses(void *info)
{
	int sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1) {
		sae_debug(SAE_DEBUG_ERR, "couldn't open NETLINK_ROUTE socket\n");
		return NULL;
	}

	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_IFADDR;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		sae_debug(SAE_DEBUG_ERR, "couldn't bind monitor_addresses socket\n");
		return NULL;
	}

	ssize_t len;
	char buffer[4096];
	while ((len = recv(sock, buffer, sizeof(buffer), 0)) != -1)
	{
		bool changed = false;
		struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
		while (NLMSG_OK(nlh, len) && nlh->nlmsg_type != NLMSG_DONE && !changed)
		{
			if (nlh->nlmsg_type == RTM_NEWADDR)
			{
				struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
				struct rtattr *rth = IFA_RTA(ifa);
				int rtl = IFA_PAYLOAD(nlh);

				while (rtl && RTA_OK(rth, rtl) && !changed) {
					if (rth->rta_type == IFA_LOCAL)
						changed = true;
					rth = RTA_NEXT(rth, rtl);
				}
			}
			nlh = NLMSG_NEXT(nlh, len);
		}

		if (changed)
		{
			sae_debug(SAE_DEBUG_PROTOCOL_MSG, "an IP address changed\n");
			on_ips_changed();
		}
	}

	shutdown(sock, SHUT_WR);
	close(sock);
	sae_debug(SAE_DEBUG_ERR, "exiting monitor_addresses thread: %s\n", strerror(errno));

	return NULL;
}

void init_watch_ips()
{
	pthread_t thread;
	int result = pthread_create(&thread, NULL, monitor_addresses, NULL);
	if (result)
        sae_debug(SAE_DEBUG_ERR, "failed to create monitor_addresses thread (%d)\n", result);
}
