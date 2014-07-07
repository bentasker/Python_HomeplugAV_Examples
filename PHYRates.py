#!/usr/bin/env python
#
# Copyright (C) 2014 B Tasker
#
# Get the PHY transfer rates
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



# We'll request the data rates between the local HPAV device and a remote one
#
#
payload='00:38:a0:00:b0:52:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'
data_list = payload.split(":")

# Breakdown of payload above
#
# '00' - MAC Management header (Version: 1) - they're zero indexed
# '38:a0' - Request type is 0xA038 (PHY data rate)
# 'b0:52' - OUI



# Build and send the packet
p = Ether()
p.src=getHwAddr(iface)
p.dst='00:B0:52:00:00:01'; # Only the nearest HomeplugAV device will respond
p.type=0x88e1; # HomeplugAV management frame
p.oui='00b052'
data=''.join(data_list).decode('hex')
b = p/data
ans = srp1(b,iface=iface)

# You should be able to see the packet leave with tcpdump -i eth0 ether dst host '00:B0:52:00:00:01'

response=''.join(ans.load).encode('hex')
response=':'.join(a+b for a,b in zip(response[::2], response[1::2]))
#print response

resp = response.split(":")

# Our values are in 38/39
print int(resp[38],16), 'Mb/s Avg Tx'
print int(resp[39],16), 'Mb/s Avg Rx'


# Example response - 00:39:a0:00:b0:52:01:b0:f2:e6:95:66:6b:03:0e:03:00:44:94:fc:9c:c7:44:02:01:44:94:fc:9c:c7:44:02:00:1f:1f:a8:92:85:63:85:00:00:00:00:00:00
# Break down of response
#
# '00' - MAC Management header (Version: 1) - they're zero indexed
# '39:a0' - Response type is 0xA039
# 'b0:52' - OUI
# '01' - 1 logical network
# 'b0:f2:e6:95:66:6b:03' - Network Id (TODO: need to see how that's calculated)
# '0e' - Short network ID
# '03' - Terminal Equipment Identifier
# '00' - Station Role - Station (00)
# '44:94:fc:9c:c7:44:02:01:44' - CCO MAC address
# '02' - CCO Terminal Equipment Identifier
# '01' - Number of AV Stations
# '44:94:fc:9c:c7:44' - MAC address of station 1
# '02' - Station Terminal Equipment Identifier
# '00:1f:1f:a8:92:85:63:85' - MAC address of first node bridged by station
# '63' - Average PHY Tx data Rate (Mb/s) - in this case 99
# '85' - Average PHY Rx data Rate (Mb/s) - in this case 133
