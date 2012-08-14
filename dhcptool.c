#include <libnet.h>
#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include "dhcptool.h"
#include "dhcp-options.h"


/* configuration variables */

int timeout;
int reply_count;
int verbosity;
int no_double_options;
char ifname[100];
char * fname;
char * sname;

u_int8_t operation;
u_int32_t xid;
u_int16_t secs;
u_int16_t flags;
u_int32_t cip;
u_int32_t yip;
u_int32_t sip;
u_int32_t gip;
u_int8_t * chaddr = NULL;
u_int8_t * ether_dst = NULL;

u_int8_t ipv4_tos;
u_int8_t ipv4_ttl;
u_int32_t ipv4_src;
u_int32_t ipv4_dst;
u_int16_t ipv4_id;


/* internal variables */

int num_options = 0;
struct dhcp_option * options = NULL;

pcap_t * pcp = NULL;
libnet_t * lnp = NULL;
char libnet_errbuf[LIBNET_ERRBUF_SIZE] = "";
char pcap_errbuf[PCAP_ERRBUF_SIZE] = "";



void usage(char *errstr) {
  if (errstr != NULL) {
    printf("Error: %s\n", errstr);
    printf("\n");
  }
  printf("DHCPTOOL %s\n", DHCPTOOL_VERSION);
  printf("\n");
  printf("Usage: dhcptool -i interface [options]\n");
  printf("\n");
  printf("options you have to set:\n");
  printf("  -i interface  Network interface to use.\n");
  printf("\n");
  printf("options you might want to set:\n");
  printf("  -o operation  DHCP message type (default: \"request\")\n");
  printf("                \"discover\" = send DHCP DISCOVER message and waits for an OFFER\n");
  printf("                \"request\"  = send DHCP REQUEST message and waits for an ACK/NAK\n");
  printf("                \"release\"  = send DHCP RELEASE message\n");
  printf("                \"decline\"  = send DHCP DECLINE message\n");
  printf("                \"inform\"   = send DHCP INFORM message and waits for an ACK\n");
  printf("  -S sip        Server IP address (gotten from OFFER, default: 0.0.0.0)\n");
  printf("  -O dhcp-opt   DHCP option, in the form \"nn=str\" or \"nn=num\"\n");
  printf("                dhcptool will try to use the correct data type for the option\n");
  printf("                (i.e. using inet_addr() to create an IP address from a string\n");
  printf("                 argument, if the DHCP option wants an IP address as argument)\n");
  printf("  -X dhcp-opt   DHCP option, in the form \"nn=hexstr\" (e.g. \"-X 50=c0a80189\")\n");
  printf("                Multiple DHCP options can be specified\n");
  printf("\n");
  printf("options with reasonable defaults:\n");
  printf("  -c cip        Client IP address (default: IP configured on interface)\n");
  printf("  -s secs       Seconds since client began acquisition process (default: 0)\n");
  printf("  -h ether      Client hardware address, chaddr (default: interface MAC address)\n");
  printf("  -x xid        Set transaction ID to \"xid\" (uint32, default: randomized)\n");
  printf("  -f flags      Bootp flags (uint16, default: 0x8000 = broadcast bit set)\n");
  printf("  -y yip        Your (client) IP address (default: 0.0.0.0)\n");
  printf("  -g gip        Gateway/relay agent IP address (default: 0.0.0.0)\n");
  printf("  -A sname      Server name string (default: \"\")\n");
  printf("  -B fname      Client boot file name string (default: \"\")\n");
  printf("  -v verbosity  How chatty we should be (default: 1)\n");
  printf("  -t timeout    Seconds to wait for any replies before exiting (default: 5)\n");
  printf("  -n reply_cnt  Maximum number of replies to wait for before exiting\n");
  printf("                (default: 0 = unlimited)\n");
  printf("  -m            Allow multiple definitions of a DHCP option (default: off)\n");
  printf("\n");
  printf("IPv4 options:\n");
  printf("  -F src_ip     (F=from) Send IP datagram from a this source IP address\n");
  printf("  -T dst_ip     (T=to) Send IP datagran to this destination IP address\n");
  printf("  -L ttl        Use this TTL value for outgoing datagrams\n");
  printf("  -Q tos        Use this type-of-service value for outgoing datagrams\n");
  printf("\n");
  printf("Ethernet options:\n");
  printf("  -E dst_ether  Use this destination MAC address (default: ff:ff:ff:ff:ff:ff)\n");
  printf("\n");
  printf("Other:\n");
  printf("  -w option     Whatis - look up a DHCP option number\n");
  printf("\n");
  exit(1);
}


int main(int argc, char **argv) {
  int ch, dhcp_payload_len;
  unsigned char *dhcp_payload;
  libnet_ptag_t ptag_dhcpv4, ptag_udp, ptag_ipv4, ptag_ethernet;

  char *arg_secs, *arg_cip, *arg_chaddr, *arg_sip, *arg_ifname;
  char *arg_operation, *arg_timeout, *arg_xid, *arg_flags, *arg_yip;
  char *arg_gip, *arg_sname, *arg_fname, *arg_ether_dst, *stmp;
  char *arg_ipv4_src, *arg_ipv4_dst, *arg_ipv4_tos, *arg_ipv4_ttl;
  char *arg_reply_count;

  if (argc < 2) usage("too few arguments");

  srandom(time(NULL));

  arg_secs = arg_cip = arg_chaddr = arg_sip = arg_ifname = NULL;
  arg_operation = arg_timeout = arg_xid = arg_flags = arg_yip = NULL;
  arg_gip = arg_sname = arg_fname = arg_ether_dst = arg_reply_count = NULL;
  arg_ipv4_src = arg_ipv4_dst = arg_ipv4_tos = arg_ipv4_ttl = NULL;
  verbosity = 1;

  while ((ch = getopt(argc, argv, "s:c:h:i:o:t:x:f:y:g:S:A:B:O:X:v:F:T:L:Q:E:w:n:m")) != -1) {
    switch (ch) {
      case 's': arg_secs = optarg; break;
      case 'c': arg_cip = optarg; break;
      case 'h': arg_chaddr = optarg; break;
      case 'S': arg_sip = optarg; break;
      case 'i': arg_ifname = optarg; break;
      case 'o': arg_operation = optarg; break;
      case 't': arg_timeout = optarg; break;
      case 'x': arg_xid = optarg; break;
      case 'f': arg_flags = optarg; break;
      case 'y': arg_yip = optarg; break;
      case 'B': arg_fname = optarg; break;
      case 'A': arg_sname = optarg; break;
      case 'g': arg_gip = optarg; break;
      case 'F': arg_ipv4_src = optarg; break;
      case 'T': arg_ipv4_dst = optarg; break;
      case 'L': arg_ipv4_ttl = optarg; break;
      case 'Q': arg_ipv4_tos = optarg; break;
      case 'n': arg_reply_count = optarg; break;
      case 'E': arg_ether_dst = optarg; break;
      case 'v': verbosity = atoi(optarg); break;
      case 'm': no_double_options = 0; break;
      case 'O': add_option(optarg); break;
      case 'X': add_hexoption(optarg); break;
      case 'w': option_lookup(optarg); break;
      case '?':
      default:
        usage("unknown argument");
    }
  }
  argc -= optind;
  argv += optind;

  /* Set some basic defaults */
  set_defaults();

  /* Make sure network interface was specified with -i option */
  if (arg_ifname == NULL) {
    usage("Error: network interface (-i option) not specified.");
  }
  strncpy(ifname, arg_ifname, 99);

  /* Try to have pcap and libnet use the interface */
  pcp = pcap_open_live(ifname, SNAPLEN, 1, 1, pcap_errbuf);
  if (pcp == NULL) {
    printf("pcap_open_live(%s) failed! Did you give the right interface name " 
           "and are you root?\n", ifname);
    printf("pcap said: %s\n", pcap_errbuf);
    exit(1);
  }
  lnp = libnet_init(LIBNET_LINK, ifname, libnet_errbuf);
  if (lnp == NULL) {
    printf("libnet_init(%s) failed!\n", ifname);
    printf("libnet said: %s\n", libnet_errbuf);
    exit(1);
  }

  /* Set chaddr MAC address */
  if (arg_chaddr != NULL) {
    int len = ETHER_ADDR_LEN;
    chaddr = libnet_hex_aton((int8_t *)arg_chaddr, &len);
    if (chaddr == NULL) {
      if (verbosity > 0)
        printf("Invalid chaddr MAC address specified (%s)\n", arg_chaddr);
      exit(1);
    }
  }
  else {
    /* Try to retrieve MAC address using libnet */
    chaddr = (u_int8_t *)libnet_get_hwaddr(lnp);
    if (chaddr == NULL) {
      if (verbosity > 1) {
        printf("Failed to retrieve MAC address for interface %s, using 0:0:0:0:0:0\n"
          "Libnet said: %s\n", ifname, libnet_errbuf);
      }
      memset(chaddr, 0, ETHER_ADDR_LEN);
    }
  }

  /* Set cip address */  
  if (arg_cip != NULL) {
    cip = inet_addr(arg_cip);
    if (cip == INADDR_NONE) {
      if (verbosity > 0) 
        printf("Invalid cip address specified (%s)\n", arg_cip);
      exit(1);
    }
    cip = ntohl(cip);
  }
  else {
    /* Try to retrieve IP address using libnet */
    cip = libnet_get_ipaddr4(lnp);
    if ((int)cip == -1) {
      if (verbosity > 1) {
        printf("Failed to retrieve IPv4 address for interface %s, using cip 0.0.0.0\n"
          "Libnet said: %s\n", ifname, libnet_errbuf);
      }
      cip = inet_addr("0.0.0.0");
    }
    else
      cip = htonl(cip);
  }


  /**************************/
  /* Set various parameters */
  /**************************/

  if (arg_operation != NULL) {
    if (option_added(LIBNET_DHCP_MESSAGETYPE) && no_double_options) {
      if (verbosity > 0) {
        printf("Error: DHCP messagetype specified twice (don't use -o option if\n"
               "       you also intend to use -O to set option 53 (messagetype))\n");
      }
      exit(1);
    }
    if (strcasecmp(arg_operation, "discover") == 0) {
      operation = LIBNET_DHCP_MSGDISCOVER;
      if (arg_timeout == NULL)
        timeout = 5;
    }
    else if (strcasecmp(arg_operation, "request") == 0) {
      operation = LIBNET_DHCP_MSGREQUEST;
      if (arg_timeout == NULL)
        timeout = 5;
    }
    else if (strcasecmp(arg_operation, "inform") == 0) {
      operation = LIBNET_DHCP_MSGINFORM;
      if (timeout == 0)
        timeout = 5;
    }
    else if (strcasecmp(arg_operation, "release") == 0)
      operation = LIBNET_DHCP_MSGRELEASE;
    else if (strcasecmp(arg_operation, "decline") == 0)
      operation = LIBNET_DHCP_MSGDECLINE;
    else {
      if (verbosity > 0)
        usage("Invalid DHCP operation type");
      else
        exit(1);
    }
    /* Add MESSAGETYPE DHCP option */
    num_options++;
    options = (struct dhcp_option *)
      realloc(options, num_options * sizeof(struct dhcp_option));
    options[num_options-1].opnum = LIBNET_DHCP_MESSAGETYPE;
    options[num_options-1].oplen = 1;
    options[num_options-1].opdata[0] = operation;
  }
  else {
    /* no "-o operation" argument given */
    if (option_added(LIBNET_DHCP_MESSAGETYPE) == 0) {
      /* Add MESSAGETYPE DHCP option */
      num_options++;
      options = (struct dhcp_option *)
        realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = LIBNET_DHCP_MESSAGETYPE;
      options[num_options-1].oplen = 1;
      options[num_options-1].opdata[0] = operation;
    }
  }

  if (arg_secs != NULL) {
    unsigned long ultmp;
    ultmp = strtoul(arg_secs, &stmp, 0);
    if (*stmp != '\0' || ultmp > 65535) {
      if (verbosity > 0)
        printf("Error: secs must be 0-65535 (was: %s)\n",
          arg_secs);
      exit(1);
    }
    secs = (u_int16_t)ultmp;
  }

  if (arg_timeout != NULL) {
    timeout = strtoul(arg_timeout, &stmp, 0);
    if (*stmp != '\0') {
      if (verbosity > 0)
        printf("Error: timeout value must be 0 or a positive integer (was: %s)\n",
          arg_timeout);
      exit(1);
    }
  }

  if (arg_reply_count != NULL) {
    reply_count = strtoul(arg_reply_count, &stmp, 0);
    if (*stmp != '\0') {
      if (verbosity > 0)
        printf("Error: reply_count value must be 0 or a positive integer (was: %s)\n",
          arg_reply_count);
      exit(1);
    }
  }

  if (arg_xid != NULL) {
    xid = strtoul(arg_xid, &stmp, 0);
    if (*stmp != '\0') {
      if (verbosity > 0) 
        printf("Error: xid value must be 0 or a positive integer (was: %s)\n",
          arg_xid);
      exit(1);
    } 
  }

  if (arg_flags != NULL) {
    unsigned long ultmp;
    ultmp = strtoul(arg_flags, &stmp, 0);
    if (*stmp != '\0' || ultmp > 65535) {
      if (verbosity > 0) 
        printf("Error: flags value must be 0-65535 (was: %s)\n",
          arg_flags);
      exit(1);
    }
    flags = (u_int16_t)ultmp;
  }

  if (arg_sip != NULL) {
    sip = inet_addr(arg_sip);
    if (sip == INADDR_NONE) {
      if (verbosity > 0)
        printf("Error: specified sip value is not a valid IPv4 address (was: %s)\n",
          arg_sip);
      exit(1);
    }
  }

  if (arg_yip != NULL) {
    yip = inet_addr(arg_yip);
    if (yip == INADDR_NONE) {
      if (verbosity > 0)
        printf("Error: specified yip value is not a valid IPv4 address (was: %s)\n",
          arg_yip);
      exit(1);
    }
  }

  if (arg_gip != NULL) {
    gip = inet_addr(arg_gip);
    if (gip == INADDR_NONE) {
      if (verbosity > 0)
        printf("Error: specified gip value is not a valid IPv4 address (was: %s)\n",
          arg_gip);
      exit(1);
    }
  }

  if (arg_fname != NULL) {
    fname = (char *)malloc(strlen(fname)+1);
    strcpy(fname, arg_fname);
  }
  if (arg_sname != NULL) {
    sname = (char *)malloc(strlen(sname)+1);
    strcpy(sname, arg_sname);
  }

  if (arg_ipv4_src != NULL) {
    ipv4_src = inet_addr(arg_ipv4_src);
    if (ipv4_src == INADDR_NONE) {
      if (verbosity > 0)
        printf("Error: specified ipv4_src value is not a valid IPv4 address (was: %s)\n",
          arg_ipv4_src);
      exit(1);
    }
  }

  if (arg_ipv4_dst != NULL) {
    ipv4_dst = inet_addr(arg_ipv4_dst);
    if (ipv4_dst == INADDR_NONE) {
      if (verbosity > 0)
        printf("Error: specified ipv4_dst value is not a valid IPv4 address (was: %s)\n",
          arg_ipv4_dst);
      exit(1);
    }
  }

  if (arg_ipv4_ttl != NULL) {
    unsigned long ultmp;
    ultmp = strtoul(arg_ipv4_ttl, &stmp, 0);
    if (*stmp != '\0' || ultmp > 255) {
      if (verbosity > 0) 
        printf("Error: ipv4_ttl value must be 0-255 (was: %s)\n",
          arg_xid);
      exit(1);
    }
    ipv4_ttl = (u_int8_t)ultmp;
  }

  if (arg_ipv4_tos != NULL) {
    unsigned long ultmp;
    ultmp = strtoul(arg_ipv4_tos, &stmp, 0);
    if (*stmp != '\0' || ultmp > 255) {
      if (verbosity > 0) 
        printf("Error: ipv4_tos value must be 0-255 (was: %s)\n",
          arg_ipv4_tos);
      exit(1);
    }
    ipv4_tos = (u_int8_t)ultmp;
  }

  if (arg_ether_dst != NULL) {
    int l = ETHER_ADDR_LEN;
    ether_dst = libnet_hex_aton((int8_t *)arg_ether_dst, &l);
    if (ether_dst == NULL) {
      if (verbosity > 0)
        printf("Error: invalid ethernet destination MAC specified (was: %s)\n",
          arg_ether_dst);
      exit(1);
    }
  }


  /******************************
   * Done setting parameters.   *
   * Start building DHCP packet *
   ******************************/

  libnet_clear_packet(lnp);

  /* Build DHCP payload (DHCP options section) */
  dhcp_payload = build_payload(&dhcp_payload_len);

  /* Create DHCP message */
  ptag_dhcpv4 = 
    libnet_build_dhcpv4(LIBNET_DHCP_REQUEST,
                         BOOTP_HTYPE_ETHER,
                         ETHER_ADDR_LEN,
                         BOOTP_HOPCOUNT,
                         xid,
                         secs,
                         flags,
                         cip,
                         yip,
                         sip,
                         gip,
                         chaddr,
                         (uint8_t *)sname,
                         (uint8_t *)fname,
                         dhcp_payload,
                         dhcp_payload_len,
                         lnp,
                         0);
  if (ptag_dhcpv4 == -1) {
    printf("Failed to build bootp packet: %s\n", libnet_errbuf);
    exit(1);
  }

/*
libnet_ptag_t
libnet_build_udp(u_int16_t sp, u_int16_t dp, u_int16_t len, u_int16_t sum,
u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
*/

  /* Create UDP datagram */
  ptag_udp =
    libnet_build_udp(UDP_SRCPORT,
                     UDP_DSTPORT,
                     dhcp_payload_len + LIBNET_DHCPV4_H + LIBNET_UDP_H,
                     0,
                     NULL,
                     0,
                     lnp,
                     0);
  if (ptag_udp == -1) {
    printf("Failed to build udp packet: %s\n", libnet_errbuf);
    exit(1);
  }

/*
libnet_ptag_t
libnet_build_ipv4(u_int16_t len, u_int8_t tos, u_int16_t id, u_int16_t frag,
u_int8_t ttl, u_int8_t prot, u_int16_t sum, u_int32_t src, u_int32_t dst,
u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
*/

  /* Create IPv4 datagram */
  ptag_ipv4 =
    libnet_build_ipv4(dhcp_payload_len + LIBNET_DHCPV4_H + LIBNET_UDP_H + LIBNET_IPV4_H,
                      ipv4_tos,
                      ipv4_id++,
                      0,
                      ipv4_ttl,
                      IPPROTO_UDP,
                      0,
                      ipv4_src,
                      ipv4_dst,
                      NULL,
                      0,
                      lnp,
                      0);
  if (ptag_ipv4 == -1) {
    printf("Failed to build ipv4 packet: %s\n", libnet_errbuf);
    exit(1);
  }

  /* Create ethernet packet */
  ptag_ethernet = 
    libnet_autobuild_ethernet(ether_dst,
                              ETHERTYPE_IP,
                              lnp);
  if (ptag_ethernet == -1) {
    printf("Failed to build ethernet packet: %s\n", libnet_errbuf);
    exit(1);
  }

  /* Write packet to network */
  if (libnet_write(lnp) == -1) {
    printf("Failed to write ethernet packet to network: %s\n", libnet_errbuf);
    exit(1);
  }

  /* If we have to wait and listen for server replies, we use
     a timer and a signal handler to quit. We do this as libpcap
     doesn't support non-blocking packet capture on some (many?)
     platforms. We could have launched another thread also, but
     using timers and signals is simpler.
   */
  if (timeout > 0) {
    struct itimerval itv;
    itv.it_interval.tv_sec = itv.it_value.tv_sec = timeout;
    itv.it_interval.tv_usec = itv.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &itv, NULL);
    signal(SIGALRM, sighandler);
    pcap_loop(pcp, -1, pcap_callback, NULL);    
  }

  libnet_destroy(lnp);
  pcap_close(pcp);
  exit(0);
}


/* sighandler()
 * This function is called through the delivery of a SIGALRM
 * signal, scheduled for when we want to stop listening for
 * incoming traffic and instead quit the program.
 */

void sighandler(int sig) {
  if (sig == SIGALRM) {
    libnet_destroy(lnp);
    pcap_close(pcp);
    exit(0);
  }
}


/* add_hexoption()
 * This function is called when the user specifies the -X argument
 * ("-X opnum=hexstr"). "hexstr" consists of one or more 
 * two-character hexadecimal values. The DHCP option length will be
 * the number of hexadecimal values so specified, and the DHCP option
 * value will be the sequence of values, each value expressed as an
 * 8-bit unsigned integer.
 */
 
void add_hexoption(char *str) {
  int opnum, oplen, tmp;
  char opdata[256];
  char *p, *p2;
  p = p2 = str;
  while (*p != '\0' && *p != '=')
    p++;
  if (*p != '=')
    return;
  *p = '\0';
  opnum = atoi(p2);
  if (opnum == 0)
    return;
  if (option_added(opnum) && no_double_options)
    return;
  p++;
  oplen = 0;
  while (sscanf(p, "%02x", &tmp) == 1) {
    opdata[oplen] = (unsigned char)tmp;
    oplen += 1;
    p += 2;
  }
  num_options++;
  options = realloc(options, num_options * sizeof(struct dhcp_option));
  options[num_options-1].opnum = opnum;
  options[num_options-1].oplen = oplen;
  memcpy(options[num_options-1].opdata, opdata, 256);
}


/* add_option()
 * This function takes a "-O opnum=opval" string and parses
 * the first part, to find out what DHCP option number is to
 * be set, then calls the appropriate add_xxx_options() function
 * to parse the following DHCP option values.
 */

void add_option(char *str) {
  int opnum, oplen;
  char opdata[256];
  char *p, *p2;
  p = p2 = str;
  while (*p != '\0' && *p != '=')
    p++;
  if (*p != '=')
    return;
  *p = '\0';
  opnum = atoi(p2);
  if (opnum == 0)
    return;
  if (option_added(opnum) && no_double_options)
    return;
  p++;
  switch (_dhcp_option_valuetype[opnum]) {
    case DHCP_OPTIONTYPE_BOOL8: 
      add_bool8_options(opnum, p); break;
    case DHCP_OPTIONTYPE_INT8: 
      add_int8_options(opnum, p); break;
    case DHCP_OPTIONTYPE_UINT8: 
      add_uint8_options(opnum, p); break;
    case DHCP_OPTIONTYPE_INT16: 
      add_int16_options(opnum, p); break;
    case DHCP_OPTIONTYPE_UINT16: 
      add_uint16_options(opnum, p); break;
    case DHCP_OPTIONTYPE_INT32: 
      add_int32_options(opnum, p); break;
    case DHCP_OPTIONTYPE_UINT32: 
      add_uint32_options(opnum, p); break;
    case DHCP_OPTIONTYPE_IPV4: 
      add_ipv4_options(opnum, p); break;
    case DHCP_OPTIONTYPE_IPV4PAIR: 
      add_ipv4pair_options(opnum, p); break;
    default: 
      /* string option assumed */
      oplen = strlen(p);
      if (oplen > 99)
        oplen = 99;
      memcpy(opdata, p, oplen);
      opdata[99] = 0x00;
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = oplen;
      memcpy(options[num_options-1].opdata, opdata, 256);
  }
}

/* build_payload()
 * This function goes through the linked list of DHCP options
 * that are to be included in the final DHCP message, and builds
 * a data buffer containing the actual data that is to be sent
 * as contents of the DHCP packet
 */

unsigned char * build_payload(int *payload_len) {
  int i, len, off;
  static unsigned char * ret = NULL;
  if (ret != NULL) {
    free(ret);
    ret = NULL;
  }
  len = 0;
  for (i = 0; i < num_options; i++) {
    len += (options[i].oplen + 2);
  }
  len += 1;
  ret = malloc(len);
  *payload_len = len;
  off = 0;
  for (i = 0; i < num_options; i++) {
    ret[off] = options[i].opnum;
    off += 1;
    ret[off] = options[i].oplen;
    off += 1;
    memcpy(ret+off, options[i].opdata, options[i].oplen);
    off += options[i].oplen;
  }
  /* add DHCP END option */
  ret[off] = 0xFF;
  return ret;
}

/*
 * pcap_callback()
 * This function is the callback function specified when calling
 * pcap_dispatch() to listen for incoming transmissions. It will
 * ignore any packets that are not identified as DHCP packets and
 * on lower verbosity levels (<2) it will also ignore DHCP request
 * packets and only print out any DHCP replies it sees.
 */

void pcap_callback(u_int8_t * userdata, 
                   const struct pcap_pkthdr *header,
                   const u_int8_t * packetbuf)
{
  u_int8_t * charp;
  u_int16_t eth_type;
  int remaining_data, i;
  struct libnet_ethernet_hdr * eth_hdr;
  struct ip * ip_pkt;
  in_addr_t src_ip, dst_ip;
  struct libnet_dhcpv4_hdr * dhcp_hdr;
  struct libnet_udp_hdr * udp_hdr;

  if (verbosity == 0)
    return;

  remaining_data = header->len;
  if (verbosity > 2)
    printf("Got a %d-byte packet!\n", header->len);

  if (remaining_data < sizeof(struct libnet_ethernet_hdr)) {
    if (verbosity > 2)
      printf("Too small to be an ethernet packet\n");
    return;
  }
  eth_hdr = (struct libnet_ethernet_hdr *)packetbuf;
  eth_type = ntohs(eth_hdr->ether_type);

  if (eth_type != ETHERTYPE_IP)
    return;

  remaining_data -= sizeof(struct libnet_ethernet_hdr);
  if (remaining_data < sizeof(struct ip)) {
    if (verbosity > 2)
      printf("ETHERTYPE was IP, but the packet is too small to be an IP packet\n");
    return;
  }
 
  ip_pkt = (struct ip *)(eth_hdr + 1);
  src_ip = ntohl(*((in_addr_t *)&(ip_pkt->ip_src)));
  dst_ip = ntohl(*((in_addr_t *)&(ip_pkt->ip_dst)));
  if (verbosity > 2) {
    printf("Got IP packet from %s ", inet_ntoa(ip_pkt->ip_src));
    printf(" to %s\n", inet_ntoa(ip_pkt->ip_dst));
  }
  if (ip_pkt->ip_p != IPPROTO_UDP)
    return;

  remaining_data -= sizeof(struct ip);
  if (remaining_data < sizeof(struct libnet_udp_hdr)) {
    if (verbosity > 2)
      printf("IPPROTO was UDP, but the packet is too small to be an UDP packet\n");
    return;
  } 
  udp_hdr = (struct libnet_udp_hdr *)(ip_pkt + 1);
  if (verbosity > 2) {
    printf("It was an UDP packet from port %d ", ntohs(udp_hdr->uh_sport));
    printf(" to port %d\n", ntohs(udp_hdr->uh_dport));
  }
  remaining_data -= sizeof(struct libnet_udp_hdr);
  if (remaining_data < sizeof(struct libnet_dhcpv4_hdr)) {
    if (verbosity > 2)
      printf("The UDP packet was too small (%d bytes) to be a DHCPv4 packet\n",
        remaining_data);
    return;
  }
  dhcp_hdr = (struct libnet_dhcpv4_hdr *)(udp_hdr + 1);
  
  if (ntohl(dhcp_hdr->dhcp_magic) != DHCP_MAGIC)
    return;

  if (verbosity > 2)
    printf("DHCP_MAGIC is OK, this seems to be a DHCPv4 packet\n");
  if (dhcp_hdr->dhcp_opcode == LIBNET_DHCP_REQUEST) {
    if (verbosity < 2)
      return;  /* ignore reuqest packets if verbosity is low */
    printf("DHCP REQUEST\n");
  }
  else if (dhcp_hdr->dhcp_opcode == LIBNET_DHCP_REPLY)
    printf("DHCP REPLY\n");
  else {
    printf("UNKNOWN OPCODE (%u)!\n", dhcp_hdr->dhcp_opcode);
    return;
  }
  printf("xid:        %u\n", (u_int32_t)ntohl(dhcp_hdr->dhcp_xid));
  printf("secs:       %u\n", (u_int32_t)ntohs(dhcp_hdr->dhcp_secs));
  printf("flags:      %u\n", (u_int32_t)ntohs(dhcp_hdr->dhcp_flags));
  printf("cip:        %s\n", inet_ntoa(*((struct in_addr *)&(dhcp_hdr->dhcp_cip))));
  printf("yip:        %s\n", inet_ntoa(*((struct in_addr *)&(dhcp_hdr->dhcp_yip))));
  printf("sip:        %s\n", inet_ntoa(*((struct in_addr *)&(dhcp_hdr->dhcp_sip))));
  printf("gip:        %s\n", inet_ntoa(*((struct in_addr *)&(dhcp_hdr->dhcp_gip))));
  printf("chaddr:     ");
  for (i = 0; i < ETHER_ADDR_LEN; i++)
    printf("%02x ", dhcp_hdr->dhcp_chaddr[i]);
  printf("\n");
  remaining_data -= sizeof(struct libnet_dhcpv4_hdr);
  charp = (u_int8_t *)(dhcp_hdr + 1);
  while (remaining_data > 0) {
    u_int8_t opnum, oplen;
    opnum = *charp;
    if (opnum == 0xff) {
      printf("Option 255:\n");
      break;
    }
    if (--remaining_data <= 0) break;
    charp++;
    oplen = *charp;
    remaining_data--;
    charp++;
    if (oplen > remaining_data) break;
    remaining_data -= oplen;
    printf("Option %03u: ", opnum);
    switch (_dhcp_option_valuetype[opnum]) {
      case DHCP_OPTIONTYPE_NONE: 
        printf("\n");
        break;
      case DHCP_OPTIONTYPE_INT8: 
        for (i = 0; i < oplen; i++, charp++) 
          printf("%d ", (int32_t)*charp);
        break;
      case DHCP_OPTIONTYPE_UINT8: 
        for (i = 0; i < oplen; i++, charp++) 
          printf("%u ", (u_int32_t)*charp);
        break;
      case DHCP_OPTIONTYPE_INT16:
        for (i = 0; i < oplen; i += 2, charp += 2)
          printf("%d ", (int32_t)ntohs(*((short *)(charp))));
        break;
      case DHCP_OPTIONTYPE_UINT16:
        for (i = 0; i < oplen; i += 2, charp += 2)
          printf("%u ", (u_int32_t)ntohs(*((unsigned short *)(charp))));
        break;
      case DHCP_OPTIONTYPE_INT32:
        for (i = 0; i < oplen; i += 4, charp += 4)
          printf("%d ", (int32_t)ntohl(*((int *)(charp))));
        break;
      case DHCP_OPTIONTYPE_UINT32:
        for (i = 0; i < oplen; i += 4, charp += 4)
          printf("%u ", (u_int32_t)ntohl(*((unsigned int *)(charp))));
        break;
      case DHCP_OPTIONTYPE_IPV4:
        for (i = 0; i < oplen; i += 4, charp += 4)
          printf("%s ", inet_ntoa(*((struct in_addr *)charp)));
        break;
      case DHCP_OPTIONTYPE_IPV4PAIR:
        for (i = 0; i < oplen; i += 8, charp += 8) {
          printf("%s:", inet_ntoa(*((struct in_addr *)charp)));
          printf("%s ", inet_ntoa(*((struct in_addr *)charp+4)));
        }
        break;
      case DHCP_OPTIONTYPE_STRING:
        for (i = 0; i < oplen; i++, charp++)
          printf("%c", *charp);
        break;
      case DHCP_OPTIONTYPE_BOOL8:
        for (i = 0; i < oplen; i++, charp++) {
          switch (*charp) {
            case 0: printf("ON");
                    break;
            case 1: printf("OFF");
                    break;
            default: printf("UNKNOWN");
          }
        }
        break;
      case DHCP_OPTIONTYPE_OPAQUE:
      case DHCP_OPTIONTYPE_UNUSED:
        for (i = 0; i < oplen; i++, charp++)
          printf("%02x", *charp);
        break;
      default:
        printf("This shouldn't happen\n");
    }
    printf("\n");
  }
  if (reply_count != 0) {
    if (--reply_count == 0)
      exit(0);
  }
}

void set_defaults() {
  int l;

  operation = LIBNET_DHCP_MSGREQUEST;

  no_double_options = 1;

  reply_count = 0;

  xid = random();
  secs = 0;
  flags = 0x8000;

  cip = inet_addr("0.0.0.0");
  yip = inet_addr("0.0.0.0");
  sip = inet_addr("0.0.0.0");
  gip = inet_addr("0.0.0.0");

  l = ETHER_ADDR_LEN;
  ether_dst = libnet_hex_aton((int8_t *)"ff:ff:ff:ff:ff:ff", &l);

  ipv4_tos = 0;
  ipv4_id = 0;
  ipv4_ttl = 255;
  ipv4_src = inet_addr("0.0.0.0");
  ipv4_dst = inet_addr("255.255.255.255");

  fname = sname = NULL;

}


int option_added(u_int8_t opnum) {
  int i;
  for (i = 0; i < num_options; i++) {
    if (options[i].opnum == opnum)
      return 1;
  }
  return 0;
}

void hexdump(u_int8_t *buf, int len) {
  int i;
  for (i = 1; i <= len; i++) {
    printf("%02x", buf[i-1]);
    if (i % 8 == 0)
      printf(" ");
    if (i % 32 == 0)
      printf("\n");
  }
}


/*
 * option_lookup()
 * This function gets called when a user specifies the -w dhcptool option
 * in order to get information about a particular DHCP option number.
 */

void option_lookup(char *str) {
  int opnum = atoi(str);
  if (opnum < 0 || opnum > 255) {
    printf("Invalid DHCP option number (%d)\n", opnum);
    exit(1);
  }
  else {
    printf("[DHCP Option %d]\n", opnum);
    printf("Description: %s\n", _dhcp_optiondesc[opnum]);
    printf("Option data type: ");
      switch (_dhcp_option_valuetype[opnum]) {
        case DHCP_OPTIONTYPE_NONE: printf("None. No value associated with option\n"); break;
        case DHCP_OPTIONTYPE_INT8: printf("8-bit signed integer (a byte/octet) value(s)\n"); break;
        case DHCP_OPTIONTYPE_UINT8: printf("8-bit unsigned integer (a byte/octet) value(s)\n"); break;
        case DHCP_OPTIONTYPE_INT16: printf("16-bit signed integer (a word) value(s)\n"); break;
        case DHCP_OPTIONTYPE_UINT16: printf("16-bit unsigned integer (a word) value(s)\n"); break;
        case DHCP_OPTIONTYPE_INT32: printf("32-bit signed integer value(s)\n"); break;
        case DHCP_OPTIONTYPE_UINT32: printf("32-bit unsigned integer value(s)\n"); break;
        case DHCP_OPTIONTYPE_STRING: printf("Character string\n"); break;
        case DHCP_OPTIONTYPE_BOOL8: printf("8-bit (a byte/octet) boolean value(s). 0x00=false, 0x01=true\n"); break;
        case DHCP_OPTIONTYPE_IPV4: printf("32-bit IPv4 address(es), network byte order\n"); break;
        case DHCP_OPTIONTYPE_IPV4PAIR: printf("Pair(s) of 32-bit IPv4 addresses, network byte order\n"); break;
        case DHCP_OPTIONTYPE_OPAQUE: printf("Opaque (undefined sequence of octets)\n"); break;
        case DHCP_OPTIONTYPE_UNUSED: printf("\n"); break;
      }
    exit(0);
  }
}


/*
 * add_xxx_options() 
 * These functions parse user-supplied strings containing option values
 * for different DHCP options. They try to extract one or more option
 * values of the correct data type (for the option in question) and
 * will report an error if the supplied string cannot be converted
 * to the correct (for the DHCP option in question) data type. Note
 * that these functions are not called when using the -X dhcptool
 * option, which lets the user specify any type of data as the DHCP 
 * option value(s).
 */

void add_ipv4_options(u_int8_t opnum, char *opdatastr) {
  in_addr_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    in_addr_t ip = inet_addr(substr);
    if (ip == INADDR_NONE && strcmp(substr, "255.255.255.255") != 0) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants an IPv4 address option value\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (in_addr_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 251) {
      *p_opdata++ = ip;
      newopt->oplen += sizeof(in_addr_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 63 IPv4 addresses\n",
          opnum);
      return;
    }
  }
}

void add_ipv4pair_options(u_int8_t opnum, char *opdatastr) {
  in_addr_t * p_opdata;
  in_addr_t ip1, ip2;
  int ip1_set;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  ip1_set = 0;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    if (!ip1_set) {
      ip1 = inet_addr(substr);
      if (ip1 == INADDR_NONE && strcmp(substr, "255.255.255.255") != 0) {
        if (verbosity > 0)
          printf("Error: DHCP option %d wants IPv4 address option values\n", 
            opnum);
        return;
      }
      ip1_set = 1;
      continue;
    }
    ip2 = inet_addr(substr);
    if (ip2 == INADDR_NONE && strcmp(substr, "255.255.255.255") != 0) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants IPv4 address option values\n", 
          opnum);
      return;
    }
    ip1_set = 0;
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (in_addr_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 247) {
      *p_opdata++ = ip1;
      *p_opdata++ = ip2;
      newopt->oplen += (sizeof(in_addr_t) * 2);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 31 IPv4 address pairs\n",
          opnum);
      return;
    }
  }
}

void add_int32_options(u_int8_t opnum, char *opdatastr) {
  int32_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    long opval;
    char *stmp;
    opval = strtol(substr, &stmp, 0);
    if (*stmp != '\0') {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 32-bit integer option values\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (int32_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 251) {
      *p_opdata++ = htonl(opval);
      newopt->oplen += sizeof(int32_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 63 32-bit values\n",
          opnum);
      return;
    }
  }
}

void add_uint32_options(u_int8_t opnum, char *opdatastr) {
  u_int32_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    unsigned long opval;
    char *stmp;
    opval = strtoul(substr, &stmp, 0);
    if (*stmp != '\0') {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 32-bit unsigned integer option values\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (u_int32_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 251) {
      *p_opdata++ = htonl(opval);
      newopt->oplen += sizeof(u_int32_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 63 32-bit values\n",
          opnum);
      return;
    }
  }
}

void add_int16_options(u_int8_t opnum, char *opdatastr) {
  int16_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    long opval;
    char *stmp;
    opval = strtol(substr, &stmp, 0);
    if (*stmp != '\0' || opval < -32768 || opval > 32768) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 16-bit integer option values (-32768 to 32768)\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (int16_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 253) {
      *p_opdata++ = htons(opval);
      newopt->oplen += sizeof(int16_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 127 16-bit values\n",
          opnum);
      return;
    }
  }
}

void add_uint16_options(u_int8_t opnum, char *opdatastr) {
  u_int16_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    unsigned long opval;
    char *stmp;
    opval = strtoul(substr, &stmp, 0);
    if (*stmp != '\0' || opval > 65535) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 16-bit unsigned integer option values (0 to 32768)\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (u_int16_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 253) {
      *p_opdata++ = htons(opval);
      newopt->oplen += sizeof(int16_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 127 16-bit values\n",
          opnum);
      return;
    }
  }
}

void add_int8_options(u_int8_t opnum, char *opdatastr) {
  int8_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    long opval;
    char *stmp;
    opval = strtol(substr, &stmp, 0);
    if (*stmp != '\0' || opval < -127 || opval > 127) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 8-bit integer option values (-127 to 127)\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (int8_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 254) {
      *p_opdata++ = opval;
      newopt->oplen += sizeof(int8_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 255 8-bit values\n",
          opnum);
      return;
    }
  }
}

void add_uint8_options(u_int8_t opnum, char *opdatastr) {
  u_int8_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    unsigned long opval;
    char *stmp;
    opval = strtoul(substr, &stmp, 0);
    if (*stmp != '\0' || opval > 255) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 8-bit integer option values (0 to 255)\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (u_int8_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 254) {
      *p_opdata++ = opval;
      newopt->oplen += sizeof(u_int8_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 255 8-bit values\n",
          opnum);
      return;
    }
  }
}

void add_bool8_options(u_int8_t opnum, char *opdatastr) {
  u_int8_t * p_opdata;
  char * substr;
  struct dhcp_option * newopt = NULL;
  char * p = opdatastr;

  for (substr = strtok(p, ":"); substr; substr = strtok(NULL, ":"))
  {
    unsigned long opval;
    char *stmp;
    opval = strtoul(substr, &stmp, 0);
    if (*stmp != '\0' || (opval != 0 && opval != 1)) {
      if (verbosity > 0)
        printf("Error: DHCP option %d wants 8-bit integer option values (boolean, 0 or 1)\n", 
          opnum);
      return;
    }
    if (newopt == NULL) {
      num_options++;
      options = realloc(options, num_options * sizeof(struct dhcp_option));
      options[num_options-1].opnum = opnum;
      options[num_options-1].oplen = 0;
      memset(options[num_options-1].opdata, 0, 256);
      newopt = &(options[num_options-1]);
      p_opdata = (u_int8_t *)(newopt->opdata);
    }
    if (newopt->oplen <= 254) {
      *p_opdata++ = opval;
      newopt->oplen += sizeof(u_int8_t);
    }
    else {
      if (verbosity > 0)
        printf("Warning: DHCP option %d can include max 255 8-bit values\n",
          opnum);
      return;
    }
  }
}

