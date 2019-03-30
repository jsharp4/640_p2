#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from queue import *
from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Apr_queue_entry(object):
    def __init__(self, packet, next_hop, next_name, count, timestamp):
        self.packet = packet
        self.next_hop = next_hop
        self.next_name = next_name
        self.count = count
        self.timestamp = timestamp

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.arp_table = dict()
        self.forwarding_table = []
        my_interfaces = net.interfaces()
        self.my_ips = [intf.ipaddr for intf in my_interfaces]
        self.mac_ip_dict = dict((intf.ipaddr, intf.ethaddr) for intf in my_interfaces)
        self.name_ip_dict = dict((intf.name, intf.ipaddr) for intf in my_interfaces)
        pkt_queue = queue()
        for intf in my_interfaces:
            i = 0
            for entry in self.forwarding_table:
                intf_addr = IPv4Network(intf.ipaddr+'/'+intf.netmask)
                entry_addr = IPv4Network(entry.ipaddr+'/'+entry.netmask)
                if intf_addr.prefixlen >= entry_addr.prefixlen:
                    break
                i += 1
            forwarding_table.insert(i, [intf.ipaddr, intf.netmask, intf.ipaddr, intf.name])
            
        table = open(“forwarding_table.txt”, “r”) 
        lines = table.readlines()
        for line in lines:
            addr = line.split()[0]
            mask = line.split()[1]
            next_hop = line.split()[2]
            name = line.split()[3]
            for entry in self.forwarding_table:
                file_addr = IPv4Network(addr+'/'+mask)
                entry_addr = IPv4Network(entry.ipaddr+'/'+entry.netmask)
                if file_addr.prefixlen >= entry_addr.prefixlen:
                    break
                i += 1
            self.forwarding_table.insert(i, [addr, mask, next_hop, name])

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
                
                for i in range(pkt_queue.qsize()):
                    dequeue_pkt = pkt_queue.get()
                    if time.time() - dequeue_pkt.timestamp >= 1:
                        if dequeue_pkt.count >= 4:
                            continue
                        dequeue_pkt.count += 1
                        dequeue_ip = self.name_ip_dict[dequeue_pkt.next_name]
                        dequeue_mac = self.mac_ip_dict[dequeue_ip]
                        arp_request = create_ip_arp_request(dequeue_ip, dequeue_mac, dequeue_pkt.next_hop)
                        self.net.send_packet(dequeue_pkt.next_name, arp_request)
                    pkt_queue.put(dequeue_pkt)
                    
                if pkt.has_header(Arp):
                    arp = pkt.get_header(Arp)
                    if arp.targetprotoaddr in self.my_ips:
                        if arp.operation == ArpOperation.Request:
                            senderhwaddr = self.mac_ip_dict[arp.targetprotoaddr]
                            senderprotoaddr = arp.targetprotoaddr
                            targethwaddr = arp.senderhwaddr
                            targetprotoaddr = arp.senderprotoaddr
                            arp_reply = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
                            self.net.send_packet(dev, arp_reply)
                        elif arp.operation == ArpOperation.Reply:
                            self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
                            for i in range(pkt_queue.qsize()):
                                dequeue_pkt = pkt_queue.get()
                                if  next_hop == arp.senderprotoaddr
                                    next_ip = self.name_ip_dict[dequeue_pkt.next_name]
                                    next_mac = self.mac_ip_dict[next_ip]
                                    ethernet_header = Ethernet(src=next_mac, dst=arp.senderhwaddr, ethertype=EtherType.IPv4)
                                    pkt.add_header(ethernet_header)
                                    self.net.send_packet(next_name, pkt)
                                    continue
                                pkt_queue.put(dequeue_pkt)

                elif pkt.has_header(Ipv4):
                    ipv4 = pkt.get_header(Ipv4)
                    ipv4.ttl -= 1
                    if ipv4.dst in my_ips:
                        continue
                    ip_addr = ipv4.dst
                    next_hop = ''
                    for entry in self.forwarding_table:
                        prefix = IPv4Address(entry[0])
                        destaddr = IPv4Address(ip_addr)
                        matches = (int(prefix) & int(destaddr)) == int(prefix)
                        if matches:
                            next_hop = entry[2]
                            next_name = entry[3]
                            break
                    if next_hop == '':
                        continue
                    if next_hop in self.arp_table:
                        ethaddr = self.arp_table[next_hop][1]
                        self.arp_table[next_hop] = [ethaddr, time.time()]
                        next_ip = self.name_ip_dict[next_name]
                        next_mac = self.mac_ip_dict[next_ip]
                        ethernet_header = Ethernet(src=next_mac, dst=ethaddr, ethertype=EtherType.IPv4)
                        pkt.add_header(ethernet_header)
                        self.net.send_packet(next_name, pkt)
                    else :
                        next_ip = self.name_ip_dict[next_name]
                        next_mac = self.mac_ip_dict[next_ip]
                        arp_request = create_ip_arp_request(next_ip, next_mac, next_hop)
                        self.net.send_packet(next_name, arp_request)
                        apr_entry = Apr_queue_entry(pkt, next_hop, next_name, 1, time.time())
                        pkt_queue.put(apr_entry)
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