
#include "include/xdefines.h"
#include "include/bits.hxx"
#include "include/networking.hxx"
#include "include/utils.hxx"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fnmatch.h>

#define HAVE_IPV6 1

#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))
#define ZERO_STRUCT(x) memset(&(x), 0, sizeof(x))
#define strchr_m strchr
static bool strequal_m(const char *s1, const char *s2)
{
	return strcmp(s1, s2) == 0;
}


/* copy from samba lib/util/util_net.c */
static void zero_sockaddr(struct sockaddr_storage *pss)
{
	/* Ensure we're at least a valid sockaddr-storage. */
	*pss = (struct sockaddr_storage) { .ss_family = AF_INET };
}

static char *normalize_ipv6_literal(const char *str, char *buf, size_t *_len)
{
#define IPv6_LITERAL_NET ".ipv6-literal.net"
	const size_t llen = sizeof(IPv6_LITERAL_NET) - 1;
	size_t len = *_len;
	int cmp;
	size_t i;
	size_t idx_chars = 0;
	size_t cnt_delimiter = 0;
	size_t cnt_chars = 0;

	if (len <= llen) {
		return NULL;
	}

	/* ignore a trailing '.' */
	if (str[len - 1] == '.') {
		len -= 1;
	}

	len -= llen;
	if (len >= INET6_ADDRSTRLEN) {
		return NULL;
	}
	if (len < 2) {
		return NULL;
	}

	cmp = strncasecmp(&str[len], IPv6_LITERAL_NET, llen);
	if (cmp != 0) {
		return NULL;
	}

	for (i = 0; i < len; i++) {
		if (idx_chars != 0) {
			break;
		}

		switch (str[i]) {
		case '-':
			buf[i] = ':';
			cnt_chars = 0;
			cnt_delimiter += 1;
			break;
		case 's':
			buf[i] = SCOPE_DELIMITER;
			idx_chars += 1;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'a':
		case 'A':
		case 'b':
		case 'B':
		case 'c':
		case 'C':
		case 'd':
		case 'D':
		case 'e':
		case 'E':
		case 'f':
		case 'F':
			buf[i] = str[i];
			cnt_chars += 1;
			break;
		default:
			return NULL;
		}
		if (cnt_chars > 4) {
			return NULL;
		}
		if (cnt_delimiter > 7) {
			return NULL;
		}
	}

	if (cnt_delimiter < 2) {
		return NULL;
	}

	for (; idx_chars != 0 && i < len; i++) {
		switch (str[i]) {
		case SCOPE_DELIMITER:
		case ':':
			return NULL;
		default:
			buf[i] = str[i];
			idx_chars += 1;
			break;
		}
	}

	if (idx_chars == 1) {
		return NULL;
	}

	buf[i] = '\0';
	*_len = len;
	return buf;
}

static bool same_net_v4(struct in_addr ip1, struct in_addr ip2, struct in_addr mask)
{
	uint32_t net1,net2,nmask;

	nmask = ntohl(mask.s_addr);
	net1  = ntohl(ip1.s_addr);
	net2  = ntohl(ip2.s_addr);
            
	return((net1 & nmask) == (net2 & nmask));
}

/**
 * Are two IPs on the same subnet?
 */
static bool same_net(const struct sockaddr *ip1,
		const struct sockaddr *ip2,
		const struct sockaddr *mask)
{
	if (ip1->sa_family != ip2->sa_family) {
		/* Never on the same net. */
		return false;
	}

#if defined(HAVE_IPV6)
	if (ip1->sa_family == AF_INET6) {
		struct sockaddr_in6 ip1_6 = *(const struct sockaddr_in6 *)ip1;
		struct sockaddr_in6 ip2_6 = *(const struct sockaddr_in6 *)ip2;
		struct sockaddr_in6 mask_6 = *(const struct sockaddr_in6 *)mask;
		char *p1 = (char *)&ip1_6.sin6_addr;
		char *p2 = (char *)&ip2_6.sin6_addr;
		char *m = (char *)&mask_6.sin6_addr;
		size_t i;

		for (i = 0; i < sizeof(struct in6_addr); i++) {
			*p1++ &= *m;
			*p2++ &= *m;
			m++;
		}
		return (memcmp(&ip1_6.sin6_addr,
				&ip2_6.sin6_addr,
				sizeof(struct in6_addr)) == 0);
	}
#endif
	if (ip1->sa_family == AF_INET) {
		return same_net_v4(((const struct sockaddr_in *)ip1)->sin_addr,
				((const struct sockaddr_in *)ip2)->sin_addr,
				((const struct sockaddr_in *)mask)->sin_addr);
	}
	return false;
}

static bool sockaddr_equal(const struct sockaddr *ip1,
		const struct sockaddr *ip2)
{
	if (ip1->sa_family != ip2->sa_family) {
		/* Never the same. */
		return false;
	}

#if defined(HAVE_IPV6)
	if (ip1->sa_family == AF_INET6) {
		return (memcmp(&((const struct sockaddr_in6 *)ip1)->sin6_addr,
				&((const struct sockaddr_in6 *)ip2)->sin6_addr,
				sizeof(struct in6_addr)) == 0);
	}
#endif
	if (ip1->sa_family == AF_INET) {
		return (memcmp(&((const struct sockaddr_in *)ip1)->sin_addr,
				&((const struct sockaddr_in *)ip2)->sin_addr,
				sizeof(struct in_addr)) == 0);
	}
	return false;
}

/**
 * Wrap getaddrinfo...
 */
static bool interpret_string_addr_internal(struct addrinfo **ppres,
		const char *str, int flags)
{
	int ret;
	struct addrinfo hints;
#if defined(HAVE_IPV6)
	char addr[INET6_ADDRSTRLEN*2] = { 0, };
	unsigned int scope_id = 0;
	size_t len = strlen(str);
#endif

	ZERO_STRUCT(hints);

	/* By default make sure it supports TCP. */
	hints.ai_socktype = SOCK_STREAM;

	/* always try as a numeric host first. This prevents unnecessary name
	 * lookups, and also ensures we accept IPv6 addresses */
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

#if defined(HAVE_IPV6)
	if (len < sizeof(addr)) {
		char *p = NULL;

		p = normalize_ipv6_literal(str, addr, &len);
		if (p != NULL) {
			hints.ai_family = AF_INET6;
			str = p;
		}
	}

	if (strchr_m(str, ':')) {
		const char *p = strchr_m(str, SCOPE_DELIMITER);

		/*
		 * Cope with link-local.
		 * This is IP:v6:addr%ifname.
		 */

		if (p && (p > str) && ((scope_id = if_nametoindex(p+1)) != 0)) {
			/* Length of string we want to copy.
			   This is IP:v6:addr (removing the %ifname).
			 */
			len = PTR_DIFF(p,str);

			if (len+1 > sizeof(addr)) {
				/* string+nul too long for array. */
				return false;
			}
			if (str != addr) {
				memcpy(addr, str, len);
			}
			addr[len] = '\0';

			str = addr;
		}
	}
#endif

	ret = getaddrinfo(str, NULL, &hints, ppres);
	if (ret == 0) {
#if defined(HAVE_IPV6)
		struct sockaddr_in6 *ps6 = NULL;

		if (scope_id == 0) {
			return true;
		}
		if (ppres == NULL) {
			return true;
		}
		if ((*ppres) == NULL) {
			return true;
		}
		if ((*ppres)->ai_addr->sa_family != AF_INET6) {
			return true;
		}

		ps6 = (struct sockaddr_in6 *)(*ppres)->ai_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&ps6->sin6_addr) &&
				ps6->sin6_scope_id == 0) {
			ps6->sin6_scope_id = scope_id;
		}
#endif

		return true;
	}

	hints.ai_flags = flags;

	/* Linux man page on getaddrinfo() says port will be
	   uninitialized when service string is NULL */

	ret = getaddrinfo(str, NULL,
			&hints,
			ppres);

	if (ret) {
		X_LOG_WARN("interpret_string_addr_internal: "
				"getaddrinfo failed for name %s (flags %d) [%s]",
				str, flags, gai_strerror(ret));
		return false;
	}
	return true;
}

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Takes a flag which allows it to
 prefer an IPv4 address (needed for DC's).
******************************************************************/

static bool interpret_string_addr_pref(struct sockaddr_storage *pss,
		const char *str,
		int flags,
		bool prefer_ipv4)
{
	struct addrinfo *res = NULL;
	int int_flags;

	zero_sockaddr(pss);

	if (flags & AI_NUMERICHOST) {
		int_flags = flags;
	} else {
		int_flags = flags|AI_ADDRCONFIG;
	}

	if (!interpret_string_addr_internal(&res, str, int_flags)) {
		return false;
	}
	if (!res) {
		return false;
	}

	if (prefer_ipv4) {
		struct addrinfo *p;

		for (p = res; p; p = p->ai_next) {
			if (p->ai_family == AF_INET) {
				memcpy(pss, p->ai_addr, p->ai_addrlen);
				break;
			}
		}
		if (p == NULL) {
			/* Copy the first sockaddr. */
			memcpy(pss, res->ai_addr, res->ai_addrlen);
		}
	} else {
		/* Copy the first sockaddr. */
		memcpy(pss, res->ai_addr, res->ai_addrlen);
	}

	freeaddrinfo(res);
	return true;
}

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Address agnostic version.
******************************************************************/

static bool interpret_string_addr(struct sockaddr_storage *pss,
		const char *str,
		int flags)
{
	return interpret_string_addr_pref(pss,
					str,
					flags,
					false);
}

/*******************************************************************
 Map a text hostname or IP address (IPv4 or IPv6) into a
 struct sockaddr_storage. Version that prefers IPv4.
******************************************************************/

static inline bool interpret_string_addr_prefer_ipv4(struct sockaddr_storage *pss,
		const char *str,
		int flags)
{
	return interpret_string_addr_pref(pss,
					str,
					flags,
					true);
}

/****************************************************************************
 Get the netmask address for a local interface.
****************************************************************************/
static void query_iface_speed_from_name(const char *name, uint64_t *speed)
{
	int ret = 0;
	struct ethtool_cmd ecmd;
	struct ethtool_value edata;
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1) {
		X_LOG_ERR("Failed to open socket.");
		return;
	}

	if (strlen(name) >= sizeof(ifr.ifr_name)) {
		X_LOG_ERR("Interface name %s too long.", name);
		goto done;
	}

	ZERO_STRUCT(ifr);
	strcpy(ifr.ifr_name, name);

	ifr.ifr_data = (char *)&edata;
	ZERO_STRUCT(edata);
	edata.cmd = ETHTOOL_GLINK;
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret == -1) {
		goto done;
	}
	if (edata.data == 0) {
		/* no link detected */
		*speed = 0;
		goto done;
	}

	ifr.ifr_data = (char *)&ecmd;
	ZERO_STRUCT(ecmd);
	ecmd.cmd = ETHTOOL_GSET;
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret == -1) {
		goto done;
	}
	/* NTNX, fsvm cannot get speed */
	if (ecmd.speed_hi == 0xffff && ecmd.speed == 0xffff) {
		*speed = 10000lu * 1000 * 1000;
	} else {
		*speed = ((uint64_t)ethtool_cmd_speed(&ecmd)) * 1000 * 1000;
	}

done:
	(void)close(fd);
}

static void query_iface_rx_queues_from_name(const char *name,
					    uint64_t *rx_queues)
{
	int ret = 0;
	struct ethtool_rxnfc rxcmd;
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1) {
		X_LOG_ERR("Failed to open socket.");
		return;
	}

	if (strlen(name) >= sizeof(ifr.ifr_name)) {
		X_LOG_ERR("Interface name %s too long.", name);
		goto done;
	}

	ZERO_STRUCT(ifr);
	strcpy(ifr.ifr_name, name);

	ifr.ifr_data = (char *)&rxcmd;
	ZERO_STRUCT(rxcmd);
	rxcmd.cmd = ETHTOOL_GRXRINGS;
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret == -1) {
		goto done;
	}

	*rx_queues = rxcmd.data;

done:
	(void)close(fd);
}

/****************************************************************************
 Create a struct sockaddr_storage with the netmask bits set to 1.
****************************************************************************/

static bool make_netmask(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			unsigned long masklen)
{
	*pss_out = *pss_in;
	/* Now apply masklen bits of mask. */
#if defined(HAVE_IPV6)
	if (pss_in->ss_family == AF_INET6) {
		char *p = (char *)&((struct sockaddr_in6 *)pss_out)->sin6_addr;
		unsigned int i;

		if (masklen > 128) {
			return false;
		}
		for (i = 0; masklen >= 8; masklen -= 8, i++) {
			*p++ = x_convert<char>(0xff);
		}
		/* Deal with the partial byte. */
		*p = x_convert<char>(*p & (0xff & ~(0xff>>masklen)));
		p++;
		i++;
		for (;i < sizeof(struct in6_addr); i++) {
			*p++ = '\0';
		}
		return true;
	}
#endif
	if (pss_in->ss_family == AF_INET) {
		if (masklen > 32) {
			return false;
		}
		((struct sockaddr_in *)pss_out)->sin_addr.s_addr =
			htonl(((0xffffffffu >> masklen) ^ 0xffffffffu));
		return true;
	}
	return false;
}

/****************************************************************************
 Create a struct sockaddr_storage set to the broadcast or network adress from
 an incoming sockaddr_storage.
****************************************************************************/

static void make_bcast_or_net(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			const struct sockaddr_storage *nmask,
			bool make_bcast_p)
{
	unsigned int i = 0, len = 0;
	const char *pmask = NULL;
	char *p = NULL;
	*pss_out = *pss_in;

	/* Set all zero netmask bits to 1. */
#if defined(HAVE_IPV6)
	if (pss_in->ss_family == AF_INET6) {
		p = (char *)&((struct sockaddr_in6 *)pss_out)->sin6_addr;
		pmask = (const char *)&((const struct sockaddr_in6 *)nmask)->sin6_addr;
		len = 16;
	}
#endif
	if (pss_in->ss_family == AF_INET) {
		p = (char *)&((struct sockaddr_in *)pss_out)->sin_addr;
		pmask = (const char *)&((const struct sockaddr_in *)nmask)->sin_addr;
		len = 4;
	}

	for (i = 0; i < len; i++, p++, pmask++) {
		if (make_bcast_p) {
			*p = x_convert<char>((*p & *pmask) | (*pmask ^ 0xff));
		} else {
			/* make_net */
			*p = (*p & *pmask);
		}
	}
}

static inline void make_bcast(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			const struct sockaddr_storage *nmask)
{
	make_bcast_or_net(pss_out, pss_in, nmask, true);
}

static inline void make_net(struct sockaddr_storage *pss_out,
			const struct sockaddr_storage *pss_in,
			const struct sockaddr_storage *nmask)
{
	make_bcast_or_net(pss_out, pss_in, nmask, false);
}

static std::ostream &operator<<(std::ostream &os, const struct sockaddr_storage &val)
{
	char buf[INET6_ADDRSTRLEN + 1];
	if (val.ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)&val;
		os << inet_ntop(val.ss_family, &sin->sin_addr, buf, sizeof buf);
	} else {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&val;
		os << inet_ntop(val.ss_family, &sin6->sin6_addr, buf, sizeof buf);
	}
	return os;
}

static std::ostream &operator<<(std::ostream &os, const x_iface_t &val)
{
	os << "#" << val.if_index << ' ' << val.name << ' ' << val.ip << '/'
		<< val.netmask << '/' << val.bcast;
	return os;
}

int x_probe_ifaces(std::vector<x_iface_t> &ifaces)
{
	int err;
	struct ifaddrs *iflist = NULL;
	err = getifaddrs(&iflist);
	X_ASSERT(err == 0);

	/* Loop through interfaces, looking for given IP address */
	for (struct ifaddrs *ifptr = iflist; ifptr != NULL; ifptr = ifptr->ifa_next) {
		uint64_t if_speed = 0;
		uint64_t rx_queues = 0;

		/* Check the interface is up. */
		if (!(ifptr->ifa_flags & IFF_UP)) {
			continue;
		}

		if ((ifptr->ifa_flags & IFF_LOOPBACK)) {
			continue;
		}

		if (!ifptr->ifa_addr || !ifptr->ifa_netmask) {
			continue;
		}

		unsigned int if_index = if_nametoindex(ifptr->ifa_name);
		if (if_index == 0) {
			X_LOG_ERR("Failed to retrieve interface index for '%s': %s",
					ifptr->ifa_name, strerror(errno));
			continue;
		}

		if (strlen(ifptr->ifa_name) >= IF_NAMESIZE) {
			/* Truncation ! Ignore. */
			X_LOG_ERR("ifa_name %s too long", ifptr->ifa_name);
			continue;
		}

		size_t copy_size;
		if (ifptr->ifa_addr->sa_family == AF_INET) {
			copy_size = sizeof(struct sockaddr_in);
		} else if (ifptr->ifa_addr->sa_family == AF_INET6) {
			copy_size = sizeof(struct sockaddr_in6);
		} else {
			continue;
		}

		struct sockaddr_storage bcast;
		/* calculate broadcast address */
		if (ifptr->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 =
				(struct sockaddr_in6 *)ifptr->ifa_addr;
			struct in6_addr *in6 =
				(struct in6_addr *)&sin6->sin6_addr;

			if (IN6_IS_ADDR_LINKLOCAL(in6) || IN6_IS_ADDR_V4COMPAT(in6)) {
				continue;
			}
			/* IPv6 does not have broadcast it uses multicast. */
			memset(&bcast, '\0', copy_size);
		} else if (ifptr->ifa_flags & (IFF_BROADCAST|IFF_LOOPBACK)) {
			make_bcast(&bcast, (const struct sockaddr_storage *)ifptr->ifa_addr, (const struct sockaddr_storage *)ifptr->ifa_netmask);
		} else if ((ifptr->ifa_flags & IFF_POINTOPOINT) &&
				ifptr->ifa_dstaddr ) {
			memcpy(&bcast, ifptr->ifa_dstaddr, copy_size);
		} else {
			continue;
		}

		ifaces.emplace_back();
		x_iface_t &iface = ifaces.back();
		ZERO_STRUCT(iface);

		iface.flags = ifptr->ifa_flags;
		iface.if_index = if_index;
		strcpy(iface.name, ifptr->ifa_name);
		memset(&iface.ip, 0, sizeof(iface.ip));
		memcpy(&iface.ip, ifptr->ifa_addr, copy_size);
		memset(&iface.netmask, 0, sizeof(iface.netmask));
		memcpy(&iface.netmask, ifptr->ifa_netmask, copy_size);
		memset(&iface.bcast, 0, sizeof(iface.bcast));
		memcpy(&iface.bcast, &bcast, copy_size);

		query_iface_speed_from_name(ifptr->ifa_name, &if_speed);
		query_iface_rx_queues_from_name(ifptr->ifa_name, &rx_queues);
		iface.linkspeed = if_speed;
		iface.capability = 0;
		/* NUTANIX-DEV, kernel not support RSS??? */
		if (true || rx_queues > 1) {
			iface.capability |= X_FSCTL_NET_IFACE_RSS_CAPABLE;
		}
		X_LOG_DBG("probe iface %s", x_tostr(iface).c_str());
	}

	freeifaddrs(iflist);
	return 0;
}
#if 0
static int iface_comp(struct iface_struct *i1, struct iface_struct *i2)
{
	int r;

#if defined(HAVE_IPV6)
	/*
	 * If we have IPv6 - sort these interfaces lower
	 * than any IPv4 ones.
	 */
	if (i1->ip.ss_family == AF_INET6 &&
			i2->ip.ss_family == AF_INET) {
		return -1;
	} else if (i1->ip.ss_family == AF_INET &&
			i2->ip.ss_family == AF_INET6) {
		return 1;
	}

	if (i1->ip.ss_family == AF_INET6) {
		struct sockaddr_in6 *s1 = (struct sockaddr_in6 *)&i1->ip;
		struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&i2->ip;

		r = memcmp(&s1->sin6_addr,
				&s2->sin6_addr,
				sizeof(struct in6_addr));
		if (r) {
			return r;
		}

		s1 = (struct sockaddr_in6 *)&i1->netmask;
		s2 = (struct sockaddr_in6 *)&i2->netmask;

		r = memcmp(&s1->sin6_addr,
				&s2->sin6_addr,
				sizeof(struct in6_addr));
		if (r) {
			return r;
		}
	}
#endif

	/* AIX uses __ss_family instead of ss_family inside of
	   sockaddr_storage. Instead of trying to figure out which field to
	   use, we can just cast it to a sockaddr.
	 */

	if (((struct sockaddr *)&i1->ip)->sa_family == AF_INET) {
		struct sockaddr_in *s1 = (struct sockaddr_in *)&i1->ip;
		struct sockaddr_in *s2 = (struct sockaddr_in *)&i2->ip;

		r = ntohl(s1->sin_addr.s_addr) -
			ntohl(s2->sin_addr.s_addr);
		if (r) {
			return r;
		}

		s1 = (struct sockaddr_in *)&i1->netmask;
		s2 = (struct sockaddr_in *)&i2->netmask;

		return ntohl(s1->sin_addr.s_addr) -
			ntohl(s2->sin_addr.s_addr);
	}
	return 0;
}

/* this wrapper is used to remove duplicates from the interface list generated
   above */
int get_interfaces(TALLOC_CTX *mem_ctx, struct iface_struct **pifaces)
{
	struct iface_struct *ifaces = NULL;
	int total, i, j;

	total = _get_interfaces(mem_ctx, &ifaces);
	/* If we have an error, no interface or just one we can leave */
	if (total <= 1) {
		*pifaces = ifaces;
		return total;
	}

	/* now we need to remove duplicates */
	TYPESAFE_QSORT(ifaces, total, iface_comp);

	for (i=1;i<total;) {
		if (iface_comp(&ifaces[i-1], &ifaces[i]) == 0) {
			for (j=i-1;j<total-1;j++) {
				ifaces[j] = ifaces[j+1];
			}
			total--;
		} else {
			i++;
		}
	}

	*pifaces = ifaces;
	return total;
}
#endif

static void parse_extra_info(char *key, uint64_t *pspeed, uint32_t *pcap,
			     uint32_t *pif_index)
{
	while (key != NULL && *key != '\0') {
		char *next_key;
		char *val;

		next_key = strchr_m(key, ',');
		if (next_key != NULL) {
			*next_key++ = 0;
		}

		val = strchr_m(key, '=');
		if (val != NULL) {
			*val++ = 0;

			if (strequal_m(key, "speed")) {
				char *end;
				uint64_t speed = strtoul(val, &end, 0);
				if (*end) {
					X_LOG_WARN("Invalid speed value (%s)", val);
				} else {
					*pspeed = speed;
				}
			} else if (strequal_m(key, "capability")) {
				if (strequal_m(val, "RSS")) {
					*pcap |= X_FSCTL_NET_IFACE_RSS_CAPABLE;
				} else if (strequal_m(val, "RDMA")) {
					*pcap |= X_FSCTL_NET_IFACE_RDMA_CAPABLE;
				} else {
					X_LOG_WARN("Capability unknown: '%s'",
							val);
				}
			} else if (strequal_m(key, "if_index")) {
				char *end;
				unsigned long if_index = strtoul(val, &end, 0);
				if (*end) {
					X_LOG_WARN("Invalid key value (%s)", val);
				}
				*pif_index = x_convert_assert<uint32_t>(if_index);
			} else {
				X_LOG_WARN("Key unknown: '%s'", key);
			}
		}

		key = next_key;
	}
}

/****************************************************************************
 Interpret a single element from a interfaces= config line.

 This handles the following different forms:

 1) wildcard interface name
 2) DNS name
 3) IP/masklen
 4) ip/mask
 5) bcast/mask

 Additional information for an interface can be specified with
 this extended syntax:

    "interface[;key1=value1[,key2=value2[...]]]"

 Note: The double quoting is important for the
       smb.conf parser! Otherwise the ';' and ',' separates
       two interfaces.

 where
 - keys known: 'speed', 'capability', 'if_index'
 - speed is in bits per second
 - capabilites known: 'RSS', 'RDMA'
 - if_index should be used with care, because
   these indexes should not conicide with indexes
   the kernel sets...

 Note: The specified values overwrite the autodetected values!

****************************************************************************/
int x_interpret_iface(std::vector<x_iface_t> &ret, std::string token_str,
		const std::vector<x_iface_t> &probed_ifaces)
{
	struct sockaddr_storage ss;
	struct sockaddr_storage ss_mask;
	struct sockaddr_storage ss_net;
	struct sockaddr_storage ss_bcast;
	char *p;
	unsigned int added = 0;
	bool goodaddr = false;
	uint64_t speed = 0;
	uint32_t cap = 0;
	uint32_t if_index = 0;
	bool speed_set = false;
	bool cap_set = false;
	bool if_index_set = false;
	char *token = token_str.data();

	/*
	 * extract speed / capability information if present
	 */
	p = strchr_m(token, ';');
	if (p != NULL) {
		*p++ = 0;
		parse_extra_info(p, &speed, &cap, &if_index);
		if (speed != 0) {
			speed_set = true;
		}
		if (cap != 0) {
			cap_set = true;
		}
		if (if_index != 0) {
			if_index_set = true;
		}
	}

	/* first check if it is an interface name */
	for (const auto &probed_iface: probed_ifaces) {
		if (fnmatch(token, probed_iface.name, 0) == 0) {
			ret.push_back(probed_iface);
			auto &iface = ret.back();
			if (speed_set) {
				iface.linkspeed = speed;
			}
			if (cap_set) {
				iface.capability = cap;
			}
			if (if_index_set) {
				iface.if_index = if_index;
			}
			++added;
		}
	}

	if (added) {
		return added;
	}

	p = strchr_m(token,'/');
	if (p == NULL) {
		if (!interpret_string_addr(&ss, token, 0)) {
			X_LOG_ERR("interpret_interface: Can't find address "
					"for %s", token);
			return added;
		}

		for (const auto &probed_iface: probed_ifaces) {
			if (sockaddr_equal((struct sockaddr *)&ss,
				(struct sockaddr *)&probed_iface.ip)) {
				ret.push_back(probed_iface);
				auto &iface = ret.back();
				if (speed_set) {
					iface.linkspeed = speed;
				}
				if (cap_set) {
					iface.capability = cap;
				}
				if (if_index_set) {
					iface.if_index = if_index;
				}
				return ++added;
			}
		}
		X_LOG_ERR("interpret_interface: "
				"can't determine interface for %s",
				token);
		return added;
	}

	/* parse it into an IP address/netmasklength pair */
	*p = 0;
	goodaddr = interpret_string_addr(&ss, token, 0);
	*p++ = '/';

	if (!goodaddr) {
		X_LOG_ERR("interpret_interface: "
			"can't determine interface for %s",
			token);
		return added;
	}

	if (strlen(p) > 2) {
		goodaddr = interpret_string_addr(&ss_mask, p, 0);
		if (!goodaddr) {
			X_LOG_ERR("interpret_interface: "
				"can't determine netmask from %s",
				p);
			return added;
		}
	} else {
		char *end;
		unsigned long val = strtoul(p, &end, 0);
		if (*end) {
			X_LOG_ERR("interpret_interface: "
				"can't determine netmask value from %s",
				p);
			return added;
		}
		if (!make_netmask(&ss_mask, &ss, val)) {
			X_LOG_ERR("interpret_interface: "
				"can't apply netmask value %lu from %s",
				val,
				p);
			return added;
		}
	}

	make_bcast(&ss_bcast, &ss, &ss_mask);
	make_net(&ss_net, &ss, &ss_mask);

	/* Maybe the first component was a broadcast address. */
	if (sockaddr_equal((struct sockaddr *)&ss_bcast, (struct sockaddr *)&ss) ||
		sockaddr_equal((struct sockaddr *)&ss_net, (struct sockaddr *)&ss)) {
		for (const auto &probed_iface: probed_ifaces) {
			if (same_net((struct sockaddr *)&ss, 
						(struct sockaddr *)&probed_iface.ip, 
						(struct sockaddr *)&ss_mask)) {
				/* Temporarily replace netmask on
				 * the detected interface - user knows
				 * best.... */
				ret.push_back(probed_iface);
				auto &iface = ret.back();
				iface.netmask = ss_mask;
				X_LOG_ERR("interpret_interface: "
					"using netmask value %s from "
					"config file on interface %s",
					p,
					iface.name);
				if (speed_set) {
					iface.linkspeed = speed;
				}
				if (cap_set) {
					iface.capability = cap;
				}
				if (if_index_set) {
					iface.if_index = if_index;
				}
				return ++added;
			}
		}
		X_LOG_ERR("interpret_interface: Can't determine ip for "
			"broadcast address %s",
			token);
		return added;
	}

	/* Just fake up the interface definition. User knows best. */

	X_LOG_ERR("interpret_interface: Adding interface %s",
		token);

	x_iface_t ifs;
	ZERO_STRUCT(ifs);
	(void)strncpy(ifs.name, token, sizeof(ifs.name));
	ifs.flags = IFF_BROADCAST;
	ifs.ip = ss;
	ifs.netmask = ss_mask;
	ifs.bcast = ss_bcast;
	if (if_index_set) {
		ifs.if_index = if_index;
	}
	if (speed_set) {
		ifs.linkspeed = speed;
	} else {
		ifs.linkspeed = 10ul * 1000 * 1000 * 1000;
	}
	ifs.capability = cap;
	ret.push_back(ifs);
	return ++added;
}


