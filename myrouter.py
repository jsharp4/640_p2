#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

#arp = packet.get_header(Arp)

#create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
#create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)

#netaddr = IPv4Network('172.16.0.0/255.255.255.0')
#netaddr.prefixlen

#prefixnet = IPv4Network('172.16.0.0/16')
	# same as IPv4Network('172.16.0.0/255.255.0.0')
#matches = destaddr in prefixnet
	#matches -> boolean

#packet.dstip == interface.ipaddr -> drop packet

#part 1--- send and receive ARP
#part 2--- route packets based one existing table
#part 3--- learn table dynamically
#part 4--- fuck it, we'll do it live

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
