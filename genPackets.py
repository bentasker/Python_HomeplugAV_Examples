#!/usr/bin/env python
#
# Copyright (C) 2014 B Tasker
#
#

import sys
sys.path.append('Scapy') # Uncomment this if you've got Scapy in a subdirectory rather than installed system wide


from scapy.all import *
from scapy.utils import rdpcap
import fcntl, socket, struct


iface='eth0' # Which interface should we use



# Function from http://stackoverflow.com/questions/159137/getting-mac-address
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]



# We'll set the encryption key (NMK) to 'HomePlugAV' - 50D3E4933F855B7040784DF815AA8DB7
#
# To generate a NMK, use hpavkey from open-plc-utils (https://github.com/qca/open-plc-utils)
#
# hpavkey -M HomePlugAV
# 50D3E4933F855B7040784DF815AA8DB7
#
# hpavkey -M StrongPassword
# 5A11F2E2B1FDA8ABFADA70B4B1B8C674


payload='00:50:a0:00:b0:52:01:50:d3:e4:93:3f:85:5b:70:40:78:4d:f8:15:aa:8d:b7:0f:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'
data_list = payload.split(":")

# Break down of payload used above
#
# '00' - MAC Management header (Version: 1) - they're zero indexed
# '50:a0' - Request is AxA050 (Encryption key set request)
# 'b0:52' - OUI
# '01' - EKS (in this case - Unknown 0x01)
# '50:d3:e4:93:3f:85:5b:70:40:78:4d:f8:15:aa:8d:b7' - Desired Crypto key (the NMK)
# '0f' - Payload encryption key select (0x0f)
# '00:00:00:00:00:00' - Destination Address
# '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00' - DAK (empty in this case)



# Build and send the packet
p = Ether()
p.src=getHwAddr(iface)
p.dst='00:B0:52:00:00:01'; # Only the nearest HomeplugAV device will respond
p.type=0x88e1; # HomeplugAV management frame
p.oui='00b052'
data=''.join(data_list).decode('hex')
b = p/data
ls(b)
sendp(b,count=1,iface=iface)

# You should be able to see the packet leave with tcpdump -i eth0 ether dst host '00:B0:52:00:00:01'
