#ifndef _DHCP_OPTIONS_H_
#define _DHCP_OPTIONS_H_

#define DHCP_OPTIONTYPE_NONE		(1)
#define DHCP_OPTIONTYPE_INT8		(2)
#define DHCP_OPTIONTYPE_INT16		(3)
#define DHCP_OPTIONTYPE_INT32		(4)
#define DHCP_OPTIONTYPE_UINT8		(5)
#define DHCP_OPTIONTYPE_UINT16		(6)
#define DHCP_OPTIONTYPE_UINT32		(7)
#define DHCP_OPTIONTYPE_IPV4		(8)
#define DHCP_OPTIONTYPE_IPV4PAIR	(9)
#define DHCP_OPTIONTYPE_STRING		(10)
#define DHCP_OPTIONTYPE_BOOL8		(11)
#define DHCP_OPTIONTYPE_OPAQUE		(12)
#define DHCP_OPTIONTYPE_UNUSED		(13)

const char * _dhcp_optiondesc[] = { \
  "Pad",\
  "Subnet Mask",\
  "Time Offset",\
  "Router",\
  "Time Server",\
  "Name Server",\
  "Domain Server",\
  "Log Server",\
  "Quotes Server",\
  "LPR Server",\
  "Impress Server",\
  "RLP Server",\
  "Hostname",\
  "Boot File Size",\
  "Merit Dump File",\
  "Domain Name",\
  "Swap Server",\
  "Root Path",\
  "Extension File",\
  "Forwarding On/Off",\
  "SrcRte On/Off",\
  "Policy Filter",\
  "Max DG Assembly",\
  "Default IP TTL",\
  "MTU Timeout",\
  "MTU Plateau",\
  "MTU Interface",\
  "MTU Subnet",\
  "Broadcast Address",\
  "Mask Discovery",\
  "Mask Supplier",\
  "Router Discovery",\
  "Router Request",\
  "Static Route",\
  "Trailers",\
  "ARP Timeout",\
  "Ethernet",\
  "Default TCP TTL",\
  "Keepalive Time",\
  "Keepalive Data",\
  "NIS Domain",\
  "NIS Servers",\
  "NTP Servers",\
  "Vendor Specific",\
  "NETBIOS Name Srv",\
  "NETBIOS Dist Srv",\
  "NETBIOS Node Type",\
  "NETBIOS Scope",\
  "X Window Font",\
  "X Window Manager",\
  "Address Request",\
  "Address Time",\
  "Overload",\
  "DHCP Msg Type",\
  "DHCP Server Id",\
  "Parameter List",\
  "DHCP Message",\
  "DHCP Max Msg Size",\
  "Renewal Time",\
  "Rebinding Time",\
  "Class Id",\
  "Client Id",\
  "Netware/IP Domain",\
  "Netware/IP Option",\
  "NIS-Domain-Name",\
  "NIS-Server-Addr",\
  "Server-Name",\
  "Bootfile-Name",\
  "Home-Agent-Addrs",\
  "SMTP-Server",\
  "POP3-Server",\
  "NNTP-Server",\
  "WWW-Server",\
  "Finger-Server",\
  "IRC-Server",\
  "StreetTalk-Server",\
  "STDA-Server",\
  "User-Class",\
  "Directory Agent",\
  "Service Scope",\
  "Rapid Commit",\
  "Client FQDN",\
  "Relay Agent Information",\
  "iSNS",\
  "[REMOVED/Unassigned]",\
  "NDS Servers",\
  "NDS Tree Name",\
  "NDS Context",\
  "BCMCS Controller Domain Name List",\
  "BCMCS Controller IPv4 address option",\
  "Authentication",\
  "client-last-transaction-time",\
  "associated-ip",\
  "Client System",\
  "Client NDI",\
  "LDAP",\
  "[REMOVED/Unassigned]",\
  "UUID/GUID",\
  "User-Auth",\
  "GEOCONF_CIVIC",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "Unassigned",\
  "[REMOVED/Unassigned]",\
  "Unassigned",\
  "Netinfo Address",\
  "Netinfo Tag",\
  "URL",\
  "[REMOVED/Unassigned]",\
  "Auto-Config",\
  "Name Service Search",\
  "Subnet Selection",\
  "Domain Search",\
  "SIP Servers DHCP",\
  "Classless Static Route",\
  "CCC",\
  "GeoConf",\
  "V-I Vendor Class",\
  "V-I Vendor-Specific Information",\
  "[REMOVED/Unassigned]",\
  "[REMOVED/Unassigned]",\
  "PXE | Etherboot | DOCSIS | TFTP",\
  "PXE | Kernel options | Call server IP",\
  "PXE | Ethernet interface | Discrimination string",\
  "PXE | Remote statistics server IP",\
  "PXE | 802.1P VLAN ID",\
  "PXE | 802.1Q L2 Priority",\
  "PXE | Diffserv Code Point",\
  "PXE | HTTP Proxy for phone-apps",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "TFTP server | Etherboot | GRUB config path",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Etherboot",\
  "IP Telephone",\
  "Etherboot | PacketCable and CableHome",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "pxelinux.magic",\
  "pxelinux.configfile",\
  "pxelinux.pathprefix",\
  "pxelinux.reboottime",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Unassigned",\
  "Subnet Allocation",\
  "Virtual Subnet Selection",\
  "Unassigned",\
  "Unassigned",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "Private Use",\
  "End"\
};

const unsigned char _dhcp_option_valuetype[] = {\
  DHCP_OPTIONTYPE_NONE,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_INT32,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_UINT16,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_IPV4PAIR,\
  DHCP_OPTIONTYPE_UINT16,\
  DHCP_OPTIONTYPE_UINT8,\
  DHCP_OPTIONTYPE_UINT32,\
  DHCP_OPTIONTYPE_UINT16,\
  DHCP_OPTIONTYPE_UINT16,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4PAIR,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_UINT32,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_UINT8,\
  DHCP_OPTIONTYPE_UINT32,\
  DHCP_OPTIONTYPE_BOOL8,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_UINT8,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_UINT32,\
  DHCP_OPTIONTYPE_UINT8,\
  DHCP_OPTIONTYPE_UINT8,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_UINT8,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_UINT16,\
  DHCP_OPTIONTYPE_UINT32,\
  DHCP_OPTIONTYPE_UINT32,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_IPV4,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_STRING,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_UNUSED,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_OPAQUE,\
  DHCP_OPTIONTYPE_NONE\
};


#endif
