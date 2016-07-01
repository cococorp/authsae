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
#include "rekey.h"

#include "peers.h"
#include "sae.h"
#include <errno.h>
#include <libconfig.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

// Multicast is not very reliable so we want to do quite a few mpings.
// (It's also helpful to give our peer some time to either send a rejection
// or resend a dropped packet).
#define MAX_TRIES 20
#define MAX_REAUTHS 4
#define MPING_MSECS 500

const char* group = "224.0.0.124";	// note that this is also hard-coded below (look for mping_recv_socket)
const int port = 4875;

static int mping_send_socket;	// need two sockets for multicast because they use different socket options
static int mping_recv_socket;
static int upong_socket;
static uint8_t my_mac[ETH_ALEN];
static uint32_t my_ip;
static service_context context;
static struct mesh_node *mesh;
static bool ips_changed = true;

#define EXPLODE_IP(ip) (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF

static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int get_mac_addr(const char* iface_name, uint8_t* mac_addr)
{
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
		return -1;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, iface_name, sizeof(ifr.ifr_name)-1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
		return -1;

	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(sock);
	return 0;
}

// This can fail for a minute or so after network restarts.
static uint32_t get_ip_addr(const char* ifname)
{
	uint32_t addr = 0;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		sae_debug(SAE_DEBUG_ERR, "error getting ip address socket: %s\n", strerror(errno));
		return addr;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	int err = ioctl(fd, SIOCGIFADDR, &ifr);
	if (err != -1)
		addr = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
	else
		sae_debug(SAE_DEBUG_ERR, "error getting IP address for %s: %s\n", ifr.ifr_name, strerror(errno));

	close(fd);

	return addr;
}

static int create_sock()
{
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		sae_debug(SAE_DEBUG_ERR, "creating rekey socket failed: %s\n", strerror(errno));
		return -1;
	}

	int reuse = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
		sae_debug(SAE_DEBUG_ERR, "failed to set reuse addr: %s\n", strerror(errno));

	return sock;
}

static int bind_sock(int sock, uint32_t ip, uint16_t port)
{
	struct sockaddr_in addr;

	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port        = htons(port);

	if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		close(sock);
		
		char str[INET_ADDRSTRLEN];
		sae_debug(SAE_DEBUG_ERR, "binding %s rekey socket failed: %s\n",
			inet_ntop(AF_INET, &(addr.sin_addr), str, INET_ADDRSTRLEN),
			strerror(errno));
		return -1;
	}

	return sock;
}

static bool join_group(int sock, uint32_t ip)
{
	struct ip_mreq mreq;

	mreq.imr_multiaddr.s_addr = inet_addr(group);
	mreq.imr_interface.s_addr = htonl(ip);

	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		sae_debug(SAE_DEBUG_ERR, "failed to join group for rekey socket: %s\n",
			strerror(errno));
		return false;
	}

	return true;
}

static void create_mping_send_socket(uint32_t ip, struct sockaddr_in *addr)
{
	mping_send_socket = create_sock();

	if (mping_send_socket >= 0) {
		mping_send_socket = bind_sock(mping_send_socket, ip, port);
		if (mping_send_socket < 0) {
			sae_debug(SAE_DEBUG_ERR, "failed to bind rekey socket: %s\n",
				strerror(errno));
			
		} else {
			uint8_t allow_looping = 0;
			if (setsockopt(mping_send_socket, IPPROTO_IP, IP_MULTICAST_IF, addr, sizeof(*addr)) < 0) {
				close(mping_send_socket);
				mping_send_socket = -1;

				sae_debug(SAE_DEBUG_ERR, "failed to set multicast iface for rekey socket: %s\n",
					strerror(errno));

			} else if (setsockopt(mping_send_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &allow_looping, sizeof(allow_looping)) < 0) {
				close(mping_send_socket);
				mping_send_socket = -1;

				sae_debug(SAE_DEBUG_ERR, "failed to disable multicast loopback for rekey socket: %s\n",
					strerror(errno));
			}
		}
	}
}

static void create_mping_recv_socket(uint32_t ip, struct sockaddr_in *addr)
{
	mping_recv_socket = create_sock();
	
	if (mping_recv_socket >= 0)
		mping_recv_socket = bind_sock(mping_recv_socket, 0xE000007C, port);	// TODO: yucky hard-coded group!

	if (mping_recv_socket >= 0 && setsockopt(mping_recv_socket, IPPROTO_IP, IP_MULTICAST_IF, addr, sizeof(*addr)) < 0) {
		close(mping_recv_socket);
		mping_recv_socket = -1;

		sae_debug(SAE_DEBUG_ERR, "failed to set multicast iface for rekey socket: %s\n",
			strerror(errno));
	}

	if (mping_recv_socket >= 0 && !join_group(mping_recv_socket, ip)) {
		close(mping_recv_socket);
		mping_recv_socket = -1;
	}
}

static void create_upong_socket(uint32_t ip)
{
	upong_socket = create_sock();

	if (upong_socket >= 0)
		upong_socket = bind_sock(upong_socket, ip, port+1);
}

void send_upong(uint32_t ip)
{
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port        = htons(port+1);

	int bytes_written = sendto(upong_socket, my_mac, ETH_ALEN, 0,
			(struct sockaddr *) &addr, sizeof(addr));

	if (bytes_written == ETH_ALEN) {
        sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey is ponging with %02X:%02X:%02X:%02X:%02X:%02X\n",
        		my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

	} else if (bytes_written < 0) {
        sae_debug(SAE_DEBUG_ERR, "rekey pong send failed: %s\n",
				strerror(errno));

	} else {
        sae_debug(SAE_DEBUG_ERR, "rekey pong send was expected to write %d bytes but wrote %d bytes\n",
        		ETH_ALEN, bytes_written);
	}
}

static void on_recv_upong(int fd, void *data)
{
	uint8_t peer_mac[ETH_ALEN];
	int bytes_read;
	struct sockaddr_storage their_addr;
	socklen_t addr_len = sizeof(their_addr);

	bytes_read = recvfrom(fd, peer_mac, sizeof(peer_mac), 0,
		(struct sockaddr *) &their_addr, &addr_len);

	if (bytes_read == sizeof(peer_mac)) {
		struct candidate *peer = find_peer(peer_mac, 1);
		char str[INET6_ADDRSTRLEN];
		if (peer) {
			sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey pong found peer %p to %s\n",
				peer, inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), str, sizeof(str)));
			srv_rem_timeout(context, peer->retry_timer);
			peer->num_rekeys = 0;

		} else {
			sae_debug(SAE_DEBUG_ERR, "rekey pong failed to find a peer for %02X:%02X:%02X:%02X:%02X:%02X from %s\n",
				peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5],
				inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), str, sizeof(str)));
		}

	} else if (bytes_read < 0) {
        sae_debug(SAE_DEBUG_ERR, "rekey pong recv failed: %s\n",
				strerror(errno));

	} else {
        sae_debug(SAE_DEBUG_ERR, "rekey pong recv was expected to read %d bytes but read %d bytes\n",
        		ETH_ALEN, bytes_read);
	}
}

void on_retry_mping(timerid id, void *data)
{
	struct candidate *peer = (struct candidate *) data;
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(group);
	addr.sin_port        = htons(port);

	peer->num_retries += 1;
	if (peer->num_retries > MAX_TRIES) {
		sae_debug(SAE_DEBUG_ERR, "giving up pinging %02X:%02X:%02X:%02X:%02X:%02X\n",
			peer->peer_mac[0], peer->peer_mac[1], peer->peer_mac[2], peer->peer_mac[3], peer->peer_mac[4], peer->peer_mac[5]);
			
		peer->num_rekeys += 1;
		if (peer->num_rekeys > MAX_REAUTHS) {
			sae_debug(SAE_DEBUG_ERR, "too many reauth attempts: link seems broken\n");
		} else {
			sae_debug(SAE_DEBUG_PROTOCOL_MSG, "reauthing again (attempt %u)\n", peer->num_rekeys);
			do_reauth(peer);
		}
		srv_rem_timeout(context, peer->retry_timer);
		return;
	}
	
	// It would be nice if we could just send our mac and reply on the their_addr
	// value from recvfrom but because of all the wacky bridging their_addr winds
	// up as a local address.
	uint32_t tmp = htonl(my_ip);

	uint8_t buffer[ETH_ALEN + sizeof(my_ip)];
	memcpy(buffer, peer->peer_mac, ETH_ALEN);
	memcpy(buffer+ETH_ALEN, &tmp, sizeof(tmp));

	int bytes_written = sendto(mping_send_socket, buffer, sizeof(buffer), 0,
			(struct sockaddr *) &addr, sizeof(addr));

	if (bytes_written == sizeof(buffer)) {
		sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey is pinging for %02X:%02X:%02X:%02X:%02X:%02X (try %u)\n",
			peer->peer_mac[0], peer->peer_mac[1], peer->peer_mac[2], peer->peer_mac[3], peer->peer_mac[4], peer->peer_mac[5],
			peer->num_retries);
		peer->retry_timer = srv_add_timeout(context, MPING_MSECS*1000, on_retry_mping, peer);

	} else if (bytes_written < 0) {
        sae_debug(SAE_DEBUG_ERR, "rekey ping send failed: %s\n",
				strerror(errno));

	} else {
        sae_debug(SAE_DEBUG_ERR, "rekey ping send was expected to write %d bytes but wrote %d bytes\n",
        		sizeof(buffer), bytes_written);
	}
}

static void open_rekey();

void send_mping(struct candidate *peer)
{
	if (ips_changed || (mping_send_socket == 0 && mping_recv_socket == 0)) {
		close_rekey();
		open_rekey();
		ips_changed = false;
	}

	if (mping_send_socket > 0 || mping_recv_socket > 0) {
		peer->num_retries = 0;
		peer->retry_timer = srv_add_timeout(context, MPING_MSECS*1000, on_retry_mping, peer);
	}
}

static void on_recv_mping(int fd, void *data)
{
	uint8_t buffer[ETH_ALEN + sizeof(my_ip)];

	int bytes_read = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
	if (bytes_read == sizeof(buffer)) {
		uint8_t candidate_mac[ETH_ALEN];
		memcpy(candidate_mac, buffer, ETH_ALEN);

		if (memcmp(candidate_mac, my_mac, ETH_ALEN) == 0) {
			uint32_t ip;
			memcpy(&ip, buffer+ETH_ALEN, sizeof(ip));
			ip = ntohl(ip);

			sae_debug(SAE_DEBUG_PROTOCOL_MSG, "rekey is sending a pong to %d.%d.%d.%d\n", EXPLODE_IP(ip));
			send_upong(ip);
		}

	} else if (bytes_read < 0) {
        sae_debug(SAE_DEBUG_ERR, "rekey ping recv failed: %s\n",
				strerror(errno));

	} else {
        sae_debug(SAE_DEBUG_ERR, "rekey ping recv was expected to read %d bytes but read %d bytes\n",
        		sizeof(buffer), bytes_read);
	}
}

static void open_rekey()
{
	bool found_mac = get_mac_addr(mesh->conf->interface, my_mac) >= 0;
	my_ip = get_ip_addr(mesh->conf->bridge);
	if (my_ip && found_mac) {
		struct sockaddr_in addr;
		bzero(&addr, sizeof(addr));
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = htonl(my_ip);
		addr.sin_port        = htons(port);
	
		char str[INET_ADDRSTRLEN];
		sae_debug(SAE_DEBUG_PROTOCOL_MSG, "registering sockets using %s (%s)\n",
				mesh->conf->bridge, inet_ntop(AF_INET, &(addr.sin_addr), str, INET_ADDRSTRLEN));
	
		sae_debug(SAE_DEBUG_PROTOCOL_MSG, "using mac %02X:%02X:%02X:%02X:%02X:%02X\n",
			my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

		create_mping_send_socket(my_ip, &addr);
		create_mping_recv_socket(my_ip, &addr);
		create_upong_socket(my_ip);
	
		if (mping_send_socket >= 0 && mping_recv_socket >= 0 && upong_socket >= 0) {
		    srv_add_input(context, mping_recv_socket, NULL, on_recv_mping);
		    srv_add_input(context, upong_socket, NULL, on_recv_upong);
		    
		} else {
			close_rekey();

			mping_send_socket = -1;
			mping_recv_socket = -1;
			upong_socket = -1;
		}
		
	} else {
		if (!my_ip)
			sae_debug(SAE_DEBUG_ERR, "%s has no IP\n", mesh->conf->bridge);
		if (!found_mac)
			sae_debug(SAE_DEBUG_ERR, "failed to get mac address of %s: %s\n",
					mesh->conf->interface, strerror(errno));
	}
}

void close_rekey()
{
	if (mping_send_socket >= 0)
		close(mping_send_socket);
	if (mping_recv_socket >= 0)
		close(mping_recv_socket);
	if (upong_socket >= 0)
		close(upong_socket);

	mping_send_socket = 0;
	mping_recv_socket = 0;
	upong_socket = 0;
}


void init_rekey(service_context srvctx, struct mesh_node *in_mesh)
{
	context = srvctx;
	mesh = in_mesh;
}

/* Note that this is *not* called from within the main thread. */
void on_ips_changed()
{
	ips_changed = true;
}


