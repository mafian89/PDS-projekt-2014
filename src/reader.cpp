#include "common.h"
#include "mymap.h"

int crawlThroughtDirTree(char * filename, std::stack<std::string> &dirs, std::vector<std::string> &files){
	struct stat sb;
	std::string result;
	DIR *dpdf;
	struct dirent *epdf;
	std::string path;

	//Pokud je to primo soubor
	if (lstat(filename, &sb) == -1) {
		perror("lstat");
		//~ printf("%s\n",strerror(errno));
		return -1;
	}
	if((sb.st_mode & S_IFMT) == S_IFREG) {
		//FILE
		files.push_back(filename);
	} else {
		dirs.push(filename);
		while(!dirs.empty()) {
			path = dirs.top();
			dirs.pop();
			dpdf = opendir(path.c_str());
			
			//~ printf("\nOpening folder: %s\n",path.c_str());
			if (dpdf != NULL){
			   while ((epdf = readdir(dpdf)) != NULL){
					if(strcmp(epdf->d_name, ".") == 0 || strcmp(epdf->d_name, "..") == 0){
						continue;
					}
					
					result = path+epdf->d_name;
					
					if (lstat(result.c_str(), &sb) == -1) {
						perror("lstat");
						return -1;
					}
					switch (sb.st_mode & S_IFMT) {
						case S_IFDIR:  
							result += "/";
							dirs.push(result);
							//~ printf("%s is DIRECTORY\n",epdf->d_name);
							break;
						case S_IFREG: 
							//~ printf("%s is FILE\n",epdf->d_name);
							files.push_back(result);
							break;
						default:       
							printf("unknown?\n");
							break;
					}
			   }
			} else {
				perror("opendir");
				return -1;
			}
			closedir(dpdf);
		}
	}
	return 0;
}
void process_flow(struct flow *fl, CMyMap & m,enum aggOptions ao,struct in6_addr mask)
{
	bool ipv4;
	//~ char srcip[INET6_ADDRSTRLEN];
	//~ char dstip[INET6_ADDRSTRLEN];
	
	aggregatedType tmp;
    tmp.packets = __builtin_bswap64(fl->packets);
    tmp.bytes = __builtin_bswap64(fl->bytes);
	
	switch (ntohl(fl->sa_family)) {
		case AF_INET:
			tmp.ipv4 = true;
			ipv4 = true;
			break;
		case AF_INET6:
			tmp.ipv4 = false;
			ipv4 = false;
			break;
	}
	
	
	if(ao == bySrcIp) {
		
		tmp.src_addr_opt = fl->src_addr;
		m.updateMap_WithoutLock(tmp.src_addr_opt, tmp);
		
	} else if(ao == byDstIp) {

		tmp.dst_addr_opt = fl->dst_addr;
		m.updateMap_WithoutLock(tmp.dst_addr_opt, tmp);
		
	} else if(ao == bySrcIp4 && ipv4) {

		tmp.src_addr_opt = fl->src_addr;
		m.updateMap_WithoutLock(tmp.src_addr_opt, tmp);
		
		//~ fprintf(stdout, "%s pkts: %"PRIi64" , bytes: %"PRIi64" \n", srcIp.c_str(), 
                                                     //~ __builtin_bswap64(fl->packets), 
                                                     //~ __builtin_bswap64(fl->bytes));
	} else if (ao == byDstIp4 && ipv4) {

		tmp.dst_addr_opt = fl->dst_addr;
		m.updateMap_WithoutLock(tmp.dst_addr_opt, tmp);
		
		//~ fprintf(stdout, "%s pkts: %"PRIi64" , bytes: %"PRIi64" \n", dstIp.c_str(), 
                                                     //~ __builtin_bswap64(fl->packets), 
                                                     //~ __builtin_bswap64(fl->bytes));
	} else if(ao == bySrcIp4Mask && ipv4) {
		
		struct in6_addr result;
		
		for(int i = 15; i >=0; i--) {
			result.s6_addr[i] = fl->src_addr.s6_addr[i] & mask.s6_addr[i];
		}
		
		tmp.src_addr_opt = result;
		m.updateMap_WithoutLock(tmp.src_addr_opt, tmp);
		
	} else if(ao == byDstIp4Mask && ipv4) {
		
		struct in6_addr result;
		
		for(int i = 15; i >=0; i--) {
			result.s6_addr[i] = fl->dst_addr.s6_addr[i] & mask.s6_addr[i];
		}
		
		tmp.dst_addr_opt = result;
		m.updateMap_WithoutLock(tmp.dst_addr_opt, tmp);
		
	} else if (ao == bySrcIp6 && !ipv4) {
		
		tmp.src_addr_opt = fl->src_addr;
		m.updateMap_WithoutLock(tmp.src_addr_opt, tmp);
		
	} else if (ao == byDstIp6 && !ipv4) {
		
		tmp.dst_addr_opt = fl->dst_addr;
		m.updateMap_WithoutLock(tmp.dst_addr_opt, tmp);
		
	} else if(ao == bySrcIp6Mask && !ipv4) {
		
		struct in6_addr result;
		
		for(int i = 15; i >=0; i--) {
			result.s6_addr[i] = fl->src_addr.s6_addr[i] & mask.s6_addr[i];
		}
		
		tmp.src_addr_opt = result;
		m.updateMap_WithoutLock(tmp.src_addr_opt, tmp);

		
	} else if(ao == byDstIp6Mask && !ipv4) {
		
		struct in6_addr result;
		
		for(int i = 15; i >=0; i--) {
			result.s6_addr[i] = fl->dst_addr.s6_addr[i] & mask.s6_addr[i];
		}
		
		tmp.dst_addr_opt = result;
		m.updateMap_WithoutLock(tmp.dst_addr_opt, tmp);
		
	}
	
	if(ao == bySrcPort) {
		tmp.keys.src_port = ntohs(fl->src_port);
		m.updateMap_WithoutLock(tmp.keys.src_port, tmp);
	} else if(ao == byDstPort) {
		tmp.keys.dst_port = ntohs(fl->dst_port);
		m.updateMap_WithoutLock(tmp.keys.dst_port, tmp);
	}
    
    //~ inet_ntop(AF_INET6, &(fl->src_addr), srcip, INET6_ADDRSTRLEN);
	//~ inet_ntop(AF_INET6, &(fl->dst_addr), dstip, INET6_ADDRSTRLEN);


	//~ fprintf(stdout, "%s:%d -> %s:%d, pkts: %"PRIi64" , bytes: %"PRIi64" \n", srcip, ntohs(fl->src_port), dstip, ntohs(fl->dst_port),
                                                     //~ __builtin_bswap64(fl->packets), 
                                                     //~ __builtin_bswap64(fl->bytes));
}

void produce(FILE * handle, CMyMap & m,const long int & count,enum aggOptions ao, struct in6_addr mask){
	struct flow fl;
	size_t n = 0;
	while ((n = fread(&fl, sizeof(struct flow), 1, handle)) != 0) {
		process_flow(&fl,m,ao,mask);
	}
}


struct mySortFuncBytes 
{
    bool operator()(const aggregatedType& a, const aggregatedType& b) const
    {
        return a.bytes > b.bytes;
    }
} bytes;

struct mySortFuncPackets
{
    bool operator()(const aggregatedType& a, const aggregatedType& b) const
    {
        return a.packets > b.packets;
    }
} packets;

int main(int argc, char *argv[])
{
	//http://www.exploringbinary.com/ten-ways-to-check-if-an-integer-is-a-power-of-two-in-c/
	//~ unsigned int
	CMyMap cm;
	enum aggOptions ao;
	enum sortOptions so;
	
	//~ cm.map.max_load_factor(2.0);
	//~ cm.mapIp.max_load_factor(2.0);
	
	const std::string argvOptions[] = {
		"packets",
		"bytes",
		"srcport",
		"dstport",
		"srcip4",
		"srcip4/",
		"srcip6",
		"srcip6/",
		"dstip4",
		"dstip4/",
		"dstip6",
		"dstip6/",
		"srcip",
		"dstip"
	};
	

	int opt;
	char *filename;
	std::string sort;
	std::string agg;
	std::string outString;
	std::string maskBits;
	int i_dec;
	std::string::size_type sz;
	std::size_t pos;
	if (argc < 7) {
		fprintf(stderr, "Usage: %s [-f filename -a aggregation -s sort]\n", argv[0]);
		return (EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "f:a:s:")) != -1) {
		switch (opt) {
			case 'f':
				filename = optarg;
				break;
			case 'a':
				agg = std::string(optarg);
				break;
			case 's':
				sort = std::string(optarg);
				break;
			default:
				fprintf(stderr, "Usage: %s [-f filename -a aggregation -s sort]\n", argv[0]);
            	return (EXIT_FAILURE);
		}	
	}
	if(sort == argvOptions[byPackets]) {
		so = byPackets;
	} else if(sort == argvOptions[byBytes]) {
		so = byBytes;
	} else {
		fprintf(stderr, "Unrecognized sort option! Available options are: packets, bytes. Entered: %s\n",sort.c_str());
		return (EXIT_FAILURE);
	}
	
	if(agg == argvOptions[bySrcPort]) {
		
		outString = "srcport";
		ao = bySrcPort;
		
	} else if(agg == argvOptions[byDstPort]) {
		
		outString = "dstport";
		ao = byDstPort;
		
	} else if(agg == argvOptions[bySrcIp]){
		
		outString = "srcip";
		ao = bySrcIp;
		
	} else if(agg == argvOptions[byDstIp]){
		
		outString = "dstip";
		ao = byDstIp;
		
	} else if(agg == argvOptions[bySrcIp4]) {
		
		outString = "srcip";
		ao = bySrcIp4;
		
	} else if((pos = agg.find(argvOptions[bySrcIp4Mask])) != std::string::npos) {
		
		maskBits = agg.erase(0,7);
		i_dec = std::stoi (maskBits,&sz);
		outString = "srcip";
		ao = bySrcIp4Mask;
		//~ printf("nasel jsem srcip4/ na pozici: %d a maska je: %s a cislem: %d\n",pos,maskBits.c_str(),i_dec);
		
	} else if(agg == argvOptions[byDstIp4]) {
		
		outString = "dstip";
		ao = byDstIp4;
		
	} else if((pos = agg.find(argvOptions[byDstIp4Mask])) != std::string::npos) {
		
		maskBits = agg.erase(0,7);
		i_dec = std::stoi (maskBits,&sz);
		outString = "dstip";
		ao = byDstIp4Mask;
		
	} else if(agg == argvOptions[bySrcIp6]) {
		
		outString = "srcip";
		ao = bySrcIp6;
		
	} else if((pos = agg.find(argvOptions[bySrcIp6Mask])) != std::string::npos) { 
		
		maskBits = agg.erase(0,7);
		i_dec = std::stoi (maskBits,&sz);
		outString = "srcip";
		ao = bySrcIp6Mask;
		
	} else if(agg == argvOptions[byDstIp6]) {
		
		outString = "dstip";
		ao = byDstIp6;
		
	} else if((pos = agg.find(argvOptions[byDstIp6Mask])) != std::string::npos) { 
		
		maskBits = agg.erase(0,7);
		i_dec = std::stoi (maskBits,&sz);
		outString = "dstip";
		ao = byDstIp6Mask;
		
	}else {
		fprintf(stderr, "Unrecognized aggregation option!"
		" Available options are:\nsrcport, dstport, "
		"srcip4, dstip4, srcip4/mask, dstip4/mask, "
		"srcip6, dstip6, srcip6/mask, dstip6/mask. "
		"\nEntered: %s\n",agg.c_str());
		return (EXIT_FAILURE);
	}
	
	//http://www.faqs.org/rfcs/rfc2553.html
	//~ char maskChar[INET6_ADDRSTRLEN];
	struct in6_addr mask;
	memset(&mask,0xFF,sizeof(struct in6_addr));
	
	//ipv4: posuv = 32-maska
	//ipv6: posuv = 128-maska
	int maskBase;
	if(ao ==  bySrcIp4Mask || ao == byDstIp4Mask) {
		if(i_dec >32 || i_dec < 1) {
			fprintf(stderr,"IPv4 mask must be in range from 1 to 32\n");
			return (EXIT_FAILURE);
		}
		//IPv4
		maskBase = 32;
		//~ for(int i=0; i<12; i++) {
			//~ mask.s6_addr[i] = 0x00;
		//~ }
	} else if (ao == bySrcIp6Mask || ao == byDstIp6Mask) {
		//IPv6
		if(i_dec >128 || i_dec < 1) {
			fprintf(stderr,"IPv6 mask must be in range from 1 to 128\n");
			return (EXIT_FAILURE);
		}
		maskBase = 128;
	}
	unsigned int posuv = maskBase - i_dec;
	
	//0 - MSB, 15 - LSB
	for(int i = 15; i >=0; i--){
		if(posuv >= 8) {
			posuv -= 8;
			mask.s6_addr[i] = mask.s6_addr[i] << 8;
		} else {
			if(posuv > 0) {
				mask.s6_addr[i] = mask.s6_addr[i] << posuv;
				posuv -= posuv;
			}
		}
	}

	//~ inet_ntop(AF_INET6, &mask, maskChar, INET6_ADDRSTRLEN);
	//~ printf("prefix: \%d mask: %s\n",i_dec,maskChar);

	std::stack<std::string> dirs;
	std::vector<std::string> files;
	crawlThroughtDirTree(filename, dirs, files);

	FILE * handle;
	struct stat filestatus;
	
	//~ stat( files[0].c_str(), &filestatus );
	//~ for(int i = 1; i <= 100; i++){
		//~ float blocks = (float)(filestatus.st_size/56)/i; 
		//~ printf("#%d %f=%ld\n",i,i*56*blocks,filestatus.st_size);
	//~ }
	
	for(unsigned int j=0;j<files.size();j++) {
		stat( files[j].c_str(), &filestatus );
		const long int blocks = (filestatus.st_size/56)/MAX_THREADS; 
		//~ printf("+------------------------+\n|FILE: %s\n",files[j].c_str());
		//~ printf("|Size in bytes: %ld in %ld blocks\n",filestatus.st_size,blocks );
		//~ printf("+------------------------+\n");
		handle = fopen(files[j].c_str(),"rb");
		std::thread prod1(produce, handle,std::ref(cm),blocks,ao,mask);
		prod1.join();
		fclose(handle);
	}
	printf("#%s,packets,bytes\n",outString.c_str());
	std::vector<aggregatedType> sorted;
	if(ao == bySrcPort || ao == byDstPort) {
		//~ for (auto& x: cm.map){
		for ( std::unordered_map<uint16_t,aggregatedType>::iterator x = cm.map.begin(); x != cm.map.end(); ++x ) {
			//~ printf("%d,%"PRIi64",%"PRIi64"\n", x.first, x.second.packets, x.second.bytes);
			aggregatedType tmp;
			switch (ao) {
				case bySrcPort:
					//~ tmp.keys.src_port = x.second.keys.src_port;
					tmp.keys.src_port = x->second.keys.src_port;
					break;
				case byDstPort:
					//~ tmp.keys.dst_port = x.second.keys.dst_port;
					tmp.keys.dst_port = x->second.keys.dst_port;
					break;
				default:
					break;
			}
			//~ tmp.packets = x.second.packets;
			//~ tmp.bytes = x.second.bytes;
			tmp.packets = x->second.packets;
			tmp.bytes = x->second.bytes;
			sorted.push_back(tmp);
		}
	} else {
		//~ for (auto& x: cm.mapIp) {
		for ( std::unordered_map<in6_addr,aggregatedType>::iterator x = cm.mapIpOpt.begin(); x != cm.mapIpOpt.end(); ++x ) {
			aggregatedType tmp;
			switch (ao) {
				case bySrcIp:
				case bySrcIp4:
				case bySrcIp4Mask:
				case bySrcIp6:
				case bySrcIp6Mask:
					//~ tmp.src_addr = x.second.src_addr;
					//~ tmp.src_addr = x->second.src_addr;
					//~ char srcip[INET6_ADDRSTRLEN];
					//~ inet_ntop(AF_INET6, &(x->second.src_addr_opt), srcip, INET6_ADDRSTRLEN);
					//~ printf("%s\n",srcip);
					tmp.src_addr_opt = x->second.src_addr_opt;
					break;
				case byDstIp:
				case byDstIp4:
				case byDstIp4Mask:
				case byDstIp6:
				case byDstIp6Mask:
					//~ tmp.dst_addr = x.second.dst_addr;
					//~ tmp.dst_addr = x->second.dst_addr;
					tmp.dst_addr_opt = x->second.dst_addr_opt;
					break;
				default:
					break;
			}
			//~ tmp.packets = x.second.packets;
			//~ tmp.bytes = x.second.bytes;
			tmp.ipv4 = x->second.ipv4;
			tmp.packets = x->second.packets;
			tmp.bytes = x->second.bytes;
			sorted.push_back(tmp);
		}
	}
	
	switch (so) {
		case byPackets:
			std::sort(sorted.begin(),sorted.end(),packets);
			break;
		case byBytes:
			std::sort(sorted.begin(),sorted.end(),bytes);
			break;
	}
	
	
	for(std::vector<aggregatedType>::iterator it=sorted.begin(); it!=sorted.end(); ++it){
		switch (ao) {
			case bySrcPort:
				printf("%d,%"PRIi64",%"PRIi64"\n", (*it).keys.src_port, (*it).packets, (*it).bytes);
				break;
			case byDstPort:
				printf("%d,%"PRIi64",%"PRIi64"\n", (*it).keys.dst_port, (*it).packets, (*it).bytes);
				break;
			case bySrcIp:
			case bySrcIp4:
			case bySrcIp4Mask:
			case bySrcIp6:
			case bySrcIp6Mask:
				char srcip[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &((*it).src_addr_opt), srcip, INET6_ADDRSTRLEN);	
				if((*it).ipv4) {
					std::string srcIp = std::string(srcip);
					srcIp.erase(0,2);
					if(srcIp.empty()) {
						srcIp = std::string("0.0.0.0");
					}
					printf("%s,%"PRIi64",%"PRIi64"\n", srcIp.c_str(), (*it).packets, (*it).bytes);
				} else {
					printf("%s,%"PRIi64",%"PRIi64"\n", srcip, (*it).packets, (*it).bytes);
				}
				//~ printf("%s,%"PRIi64",%"PRIi64"\n", (*it).src_addr.c_str(), (*it).packets, (*it).bytes);
				break;
			case byDstIp:
			case byDstIp4:
			case byDstIp4Mask:
			case byDstIp6:
			case byDstIp6Mask:
				char dstip[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &((*it).dst_addr_opt), dstip, INET6_ADDRSTRLEN);
				if((*it).ipv4) {
					std::string dstIp = std::string(dstip);
					dstIp.erase(0,2);
					if(dstIp.empty()) {
						dstIp = std::string("0.0.0.0");
					}
					printf("%s,%"PRIi64",%"PRIi64"\n", dstIp.c_str(), (*it).packets, (*it).bytes);
				} else {
					printf("%s,%"PRIi64",%"PRIi64"\n", dstip, (*it).packets, (*it).bytes);
				}
				//~ printf("%s,%"PRIi64",%"PRIi64"\n", (*it).dst_addr.c_str(), (*it).packets, (*it).bytes);
				break;
			default:
				break;
		}
	}

	return (EXIT_SUCCESS);
}
