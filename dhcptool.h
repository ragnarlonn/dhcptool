#ifndef _DHCPTOOL_H_
#define _DHCPTOOL_H_

#define DHCPTOOL_VERSION	"0.9b"

#define SNAPLEN 1550

#define BOOTP_HTYPE_ETHER	(0x01)
#define BOOTP_HOPCOUNT		(0x00)
#define UDP_SRCPORT		(68)
#define UDP_DSTPORT		(67)

#ifndef IPPROTO_UDP
#define IPPROTO_UDP (17)
#endif

struct dhcp_option {
  unsigned char opnum;
  unsigned char oplen;
  unsigned char opdata[256];
};

/* prototypes */
unsigned char * build_payload(int *payload_len);
void add_option(char *str);
void add_hexoption(char *str);
void usage(char *errstr);
void sighandler(int sig);
void hexdump(u_int8_t *buf, int len);
void set_defaults();
void option_lookup(char *str);
int option_added(u_int8_t opnum);
void add_int32_options(u_int8_t opnum, char *opdatastr);
void add_uint32_options(u_int8_t opnum, char *opdatastr);
void add_int16_options(u_int8_t opnum, char *opdatastr);
void add_uint16_options(u_int8_t opnum, char *opdatastr);
void add_int8_options(u_int8_t opnum, char *opdatastr);
void add_uint8_options(u_int8_t opnum, char *opdatastr);
void add_bool8_options(u_int8_t opnum, char *opdatastr);
void add_ipv4_options(u_int8_t opnum, char *opdatastr);
void add_ipv4pair_options(u_int8_t opnum, char *opdatastr);
void pcap_callback(u_int8_t * userdata, 
                   const struct pcap_pkthdr *header,
                   const u_int8_t * packetbuf);

#endif
