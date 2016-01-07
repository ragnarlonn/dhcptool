# dhcptool
Tool for testing/debugging DHCP servers

dhcptool allows you to craft your own, custom DHCP request packets that may be malformed and/or in violation of the DHCP protocol, in order to test a DHCP server and its ability to handle broken clients. dhcptool can of course be used to generate perfectly legitimate DHCP requests also.

### Example 1:

Broadcasting a DHCP DISCOVER request through interface em0, asking for parameters 1 (subnet mask), 3 (router), 6 (domain name server) and using transaction ID 12345:

```
# dhcptool -i em0 -o discover -x 12345 -O 55=1:3:6
DHCP REPLY
xid:        12345
secs:       0
flags:      32768
cip:        0.0.0.0
yip:        10.103.128.97
sip:        0.0.0.0
gip:        0.0.0.0
chaddr:     00 03 ba 96 7c e8
Option 053: 2
Option 001: 255.255.254.0
Option 003: 10.103.128.1
Option 028: 10.103.129.255
Option 054: 10.103.128.1
Option 006: 10.64.1.253
Option 051: 120
Option 058: 60
Option 059: 105
Option 255:
```


### Example 2:

Asking server 10.103.128.1 to give us IP address 10.103.128.97 (DHCP option 50), using the same transaction ID as in the above DISCOVER message:
```
#  dhcptool -i em0 -o request -x 12345 -S 10.103.128.1 -O 50=10.103.128.97 -O 55=1:3:6
DHCP REPLY
xid:        12345
secs:       0
flags:      32768
cip:        0.0.0.0
yip:        10.103.128.97
sip:        10.103.128.1
gip:        0.0.0.0
chaddr:     00 03 ba 96 7c e8
Option 053: 2
Option 001: 255.255.254.0
Option 003: 10.103.128.1
Option 028: 10.103.129.255
Option 054: 10.103.128.1
Option 006: 10.64.1.253
Option 051: 120
Option 058: 60
Option 059: 105
Option 255:
```

### Dependencies
dhcptool is dependent on pcap(3) - http://www.tcpdump.org/ and libnet - https://github.com/sam-github/libnet
