NAME=flow
COMPILER=g++
FLAGS = -std=c++0x -O2 -pthread -D __STDC_LIMIT_MACROS -D __STDC_FORMAT_MACROS

FILES=reader.cpp mymap.cpp mymap.h

ALL: $(FILES)
	$(COMPILER) $(FLAGS) -o $(NAME) $(FILES)
	
run_ultimate:
	clear
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip4/24 -s bytes > moje_out/f_1100_a_srcip4_24_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip4/24 -s packets > moje_out/f_1100_a_srcip4_24_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip4/28 -s bytes > moje_out/f_1100_a_srcip4_28_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip4/28 -s packets > moje_out/f_1100_a_srcip4_28_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip4/32 -s bytes > moje_out/f_1100_a_srcip4_32_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip4/32 -s packets > moje_out/f_1100_a_srcip4_32_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip4/24 -s bytes > moje_out/f_1100_a_dstip4_24_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip4/24 -s packets > moje_out/f_1100_a_dstip4_24_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip4/28 -s bytes > moje_out/f_1100_a_dstip4_28_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip4/28 -s packets > moje_out/f_1100_a_dstip4_28_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip4/32 -s bytes > moje_out/f_1100_a_dstip4_32_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip4/32 -s packets > moje_out/f_1100_a_dstip4_32_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip6/48 -s bytes > moje_out/f_1100_a_srcip6_48_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip6/48 -s packets > moje_out/f_1100_a_srcip6_48_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip6/68 -s bytes > moje_out/f_1100_a_srcip6_68_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip6/68 -s packets > moje_out/f_1100_a_srcip6_68_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip6/128 -s bytes > moje_out/f_1100_a_srcip6_128_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip6/128 -s packets > moje_out/f_1100_a_srcip6_128_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip6/48 -s bytes > moje_out/f_1100_a_dstip6_48_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip6/48 -s packets > moje_out/f_1100_a_dstip6_48_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip6/68 -s bytes > moje_out/f_1100_a_dstip6_68_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip6/68 -s packets > moje_out/f_1100_a_dstip6_68_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip6/128 -s bytes > moje_out/f_1100_a_dstip6_128_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip6/128 -s packets > moje_out/f_1100_a_dstip6_128_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip -s bytes > moje_out/f_1100_a_srcip_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcip -s packets > moje_out/f_1100_a_srcip_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip -s bytes > moje_out/f_1100_a_dstip_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstip -s packets > moje_out/f_1100_a_dstip_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcport -s bytes > moje_out/f_1100_a_srcport_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a srcport -s packets > moje_out/f_1100_a_srcport_s_packets
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstport -s bytes > moje_out/f_1100_a_dstport_s_bytes
	./$(NAME) -f ../data/nfcapd.201401271100.bin -a dstport -s packets > moje_out/f_1100_a_dstport_s_packets
	

clean_cache:
	sudo sh -c "sync; echo 3 > /proc/sys/vm/drop_caches"

clean:
	rm -f *.o $(NAME) *~ *.exe
