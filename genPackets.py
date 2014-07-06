#
#
#
#

import sys
sys.path.append( 'Scapy')

# Import Scapy
from scapy.all import *
from scapy.utils import rdpcap
import fcntl, socket, struct


iface='eth0' # Which interface should we use



# Function from http://stackoverflow.com/questions/159137/getting-mac-address
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]


# Set the encryption key to 'HomePlugAV' - 50D3E4933F855B7040784DF815AA8DB7
payload='00:50:a0:00:b0:52:01:50:d3:e4:93:3f:85:5b:70:40:78:4d:f8:15:aa:8d:b7:0f:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00' # Grabbed from tcpdump for now
data_list = payload.split(":")


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
