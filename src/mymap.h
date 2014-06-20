#ifndef MYMAP_H
#define MYMAP_H

#include "common.h"

namespace std {
template <>
	class hash<in6_addr> {
		public:
		  size_t operator()(const in6_addr &a) const
		  {
			return (a.s6_addr32[0] ^ a.s6_addr32[1] ^ a.s6_addr32[2] ^ a.s6_addr32[3]);
		  }
	};
}

struct KeyHash {
	 std::size_t operator()(const in6_addr& k) const
	 {
				return std::hash<in6_addr>()(k);
	 }
};
 
struct KeyEqual {
 bool operator()(const in6_addr& lhs, const in6_addr& rhs) const
 {
	for(int i= 0; i < 4; i++) {
		if(lhs.s6_addr32[i] != rhs.s6_addr32[i]) {
			return false;
		}
	}
	return true;
 }
};

class CMyMap {
	public: 
		CMyMap();
		~CMyMap();
		void updateMap(uint16_t key, aggregatedType val);
		void updateMap(std::string key, aggregatedType val);
		void updateMap_WithoutLock(std::string key, aggregatedType val);
		void updateMap_WithoutLock(uint16_t key, aggregatedType val);
		void updateMap_WithoutLock(in6_addr key, aggregatedType val);
		std::unordered_map<uint16_t,aggregatedType> map;
		std::unordered_map<std::string,aggregatedType> mapIp;
		std::unordered_map<in6_addr, aggregatedType, KeyHash, KeyEqual> mapIpOpt;
	private:
		std::mutex m;
		
};

#endif
