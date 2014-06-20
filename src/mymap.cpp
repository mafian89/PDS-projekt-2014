#include "mymap.h"

CMyMap::CMyMap(){
}

CMyMap::~CMyMap(){
}

void CMyMap::updateMap_WithoutLock(in6_addr key, aggregatedType val) {
	//Je tam hodnota?
	std::unordered_map<in6_addr,aggregatedType>::iterator got = mapIpOpt.find (key);
	
	//Test
	if ( got == mapIpOpt.end() ) {
		//vlozime
		mapIpOpt.insert ({ key,val }); 
	} else {
		//~ char srcip[INET6_ADDRSTRLEN];
		//~ inet_ntop(AF_INET6, &((got->second).src_addr_opt), srcip, INET6_ADDRSTRLEN);
		//~ printf("%s\n",srcip);
		//udelame sumu	
		(got->second).packets += val.packets;
		(got->second).bytes += val.bytes;
	}
}


void CMyMap::updateMap_WithoutLock(std::string key, aggregatedType val) {
	//Je tam hodnota?
	std::unordered_map<std::string,aggregatedType>::iterator got = mapIp.find (key);
	
	//Test
	if ( got == mapIp.end() ) {
		//vlozime
		mapIp.insert ({ key,val }); 
	} else {
		//udelame sumu	
		(got->second).packets += val.packets;
		(got->second).bytes += val.bytes;
	}
	//~ printf("%d\n",mapIp.bucket_count());
}

void CMyMap::updateMap_WithoutLock(uint16_t key, aggregatedType val) {
		//Je tam hodnota?
	std::unordered_map<uint16_t,aggregatedType>::iterator got = map.find (key);
	
	//~ printf("%d,%"PRIi64",%"PRIi64"\n", ntohs(key), __builtin_bswap64(val.packets), __builtin_bswap64(val.bytes));
	
	//Test
	if ( got == map.end() ) {
		//vlozime
		map.insert ({ key,val }); 
	} else {
		//udelame sumu	
		(got->second).packets += val.packets;
		(got->second).bytes += val.bytes;
	}
}

void CMyMap::updateMap(std::string key, aggregatedType val){
	std::unique_lock<std::mutex> mlock(m);
	//Je tam hodnota?
	std::unordered_map<std::string,aggregatedType>::iterator got = mapIp.find (key);
	
	//Test
	if ( got == mapIp.end() ) {
		//vlozime
		mapIp.insert ({ key,val }); 
	} else {
		//udelame sumu	
		(got->second).packets += val.packets;
		(got->second).bytes += val.bytes;
	}
}

void CMyMap::updateMap(uint16_t key, aggregatedType val) {
	std::unique_lock<std::mutex> mlock(m);
	//Je tam hodnota?
	std::unordered_map<uint16_t,aggregatedType>::iterator got = map.find (key);
	
	//~ printf("%d,%"PRIi64",%"PRIi64"\n", ntohs(key), __builtin_bswap64(val.packets), __builtin_bswap64(val.bytes));
	
	//Test
	if ( got == map.end() ) {
		//vlozime
		map.insert ({ key,val }); 
	} else {
		//udelame sumu	
		(got->second).packets += val.packets;
		(got->second).bytes += val.bytes;
	}
	//~ printf("CMyMap: Update DONE!\n");
	//~ mlock.unlock();
}
