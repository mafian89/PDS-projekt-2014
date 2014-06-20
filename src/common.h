#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
//~ #include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <string.h>
#include <vector>
#include <string>
#include <stack>
#include <cerrno>
#include <thread>
#include <chrono>
#include <mutex>
#include <unordered_map>
//~ #include <map>
#include <algorithm>

//Defines number of threads, which read from buffer - Must be power of 2 
#define MAX_THREADS 1

struct flow {
	uint32_t		sa_family;
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	uint16_t		src_port;
	uint16_t		dst_port;
	uint64_t        packets;
	uint64_t        bytes;
}; 

typedef struct aggregation {
	union {
		//~ struct in6_addr src_addr;
		//~ struct in6_addr dst_addr;
		uint16_t		src_port;
		uint16_t		dst_port;
	}keys;
	std::string 	src_addr;
	std::string 	dst_addr;
	struct in6_addr src_addr_opt;
	struct in6_addr dst_addr_opt;
	struct in6_addr	mask;
	bool 			ipv4;
	uint64_t        packets;
	uint64_t        bytes;
}aggregatedType;

enum aggOptions {
	bySrcPort = 2,
	byDstPort,
	bySrcIp4,
	bySrcIp4Mask,
	bySrcIp6,
	bySrcIp6Mask,
	byDstIp4,
	byDstIp4Mask,
	byDstIp6,
	byDstIp6Mask,
	bySrcIp,
	byDstIp
};

enum sortOptions {
	byPackets = 0,
	byBytes
};


#endif
