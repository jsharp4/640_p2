#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from dynamicroutingmessage import DynamicRoutingMessage

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
        self.pkt_queue = Queue()
        
        for intf in my_interfaces:
            i = 0
            for entry in self.forwarding_table:
                intf_addr = IPv4Network('0.0.0.0' +'/'+ str(intf.netmask))
                entry_addr = IPv4Network('0.0.0.0' +'/'+ str(entry[1]))
                if intf_addr.prefixlen >= entry_addr.prefixlen:
                    break
                i += 1
            self.forwarding_table.insert(i, [intf.ipaddr, intf.netmask, None, intf.name])
		    
        table = open("./forwarding_table.txt", "r") 
        lines = table.readlines()
        for line in lines:
            addr = line.split()[0]
            mask = line.split()[1]
            next_hop = line.split()[2]
            name = line.split()[3]
            i = 0
            for entry in self.forwarding_table:
                file_addr = IPv4Network(addr+'/'+mask)
                entry_addr = IPv4Network('0.0.0.0' +'/'+ str(entry[1]))
                if file_addr.prefixlen >= entry_addr.prefixlen:
                    break
                i += 1
            self.forwarding_table.insert(i, [addr, mask, next_hop, name])

        #for entry in self.forwarding_table:
        #    log_debug("### " + str(entry[0]) + "---" + str(entry[1]) + "---" + str(entry[2]) + "---" + str(entry[3]) + "###")

        self.dynamic_fwd_table = [None] * 5


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
                
                
                    
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
                            #log_debug("@@@@@@@@@@ SENDING ARP REPLY")
                        elif arp.operation == ArpOperation.Reply:
                            self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
                            for i in range(self.pkt_queue.qsize()):
                                dequeue_pkt = self.pkt_queue.get()
                                if  dequeue_pkt.next_hop == arp.senderprotoaddr:
                                    next_ip = self.name_ip_dict[dequeue_pkt.next_name]
                                    next_mac = self.mac_ip_dict[next_ip]
                                    #ethernet_header = Ethernet(src=next_mac, dst=arp.senderhwaddr, ethertype=EtherType.IPv4)
                                    out_pkt = dequeue_pkt.packet
                                    out_pkt[Ethernet].dst = arp.senderhwaddr
                                    out_pkt[Ethernet].src = next_mac
                                    #log_debug("BBBBBBBBBBBBBB SENDING DEQUEUED PACKET")
                                    self.net.send_packet(next_name, out_pkt)
                                    continue
                                self.pkt_queue.put(dequeue_pkt)
                elif pkt.has_header(DynamicRoutingMessage):
					dynamic_header = pkt.get_header(DynamicRoutingMessage)
                    oldest_time = time.time()
                    oldest_index = 0

                    for i in range(0, 4):
                        entry = self.dynamic_fwd_table[i]
                        if entry is None:
                            self.dynamic_fwd_table[i] = [dynamic_header.advertised_prefix, dynamic_header.advertised_mask, dynamic_header.next_hop, dev, time.time()]
                            break
                        elif entry[0] == dynamic_header.advertised_prefix and entry[1] == dynamic_header.advertised_mask:
                            self.dynamic_fwd_table[i][2] = dynamic_header.next_hop	
                            self.dynamic_fwd_table[i][3] = dev							
                            self.dynamic_fwd_table[i][4] = time.time()
							break
						elif IPv4Network(str(entry[0])+'/'+ str(entry[1])).prefixlen() < IPv4Network(str(dynamic_header.advertised_prefix)+'/'+ str(dynamic_header.advertised_mask)).prefixlen():
							self.dynamic_fwd_table.insert(i, [dynamic_header.advertised_prefix, dynamic_header.advertised_mask, dynamic_header.next_hop, dev, time.time()])
							if self.dynamic_fwd_table[5] is None:
								self.dynamic_fwd_table.remove(5)
							else:
								oldest_time = time.time()
								oldest_index = 0
								for i in range(0, 5):
									if dynamic_fwd_table[i][4] < oldest_time:
										oldest_index = i
								dynamic_fwd_table.remove(oldest_index)
						else:
							self.dynamic_fwd_table.insert(5, [dynamic_header.advertised_prefix, dynamic_header.advertised_mask, dynamic_header.next_hop, dev, time.time()])
							oldest_time = time.time()
							oldest_index = 0
							for i in range(0, 5):
								if dynamic_fwd_table[i][4] < oldest_time:
									oldest_index = i
							self.dynamic_fwd_table.remove(oldest_index)
                elif pkt.has_header(IPv4):
                    ipv4 = pkt.get_header(IPv4)
                    ipv4.ttl -= 1
                    if ipv4.dst in self.my_ips:
                        continue
                    ip_addr = ipv4.dst
                    next_hop = ''
					for dynamic_entry in self.dynamic_fwd_table:
                        prefix = IPv4Address(dynamic_entry[0])
                        mask = IPv4Address(dynamic_entry[1])
                        destaddr = IPv4Address(ip_addr)
                        matches = (int(mask) & int(destaddr)) == (int(prefix) & int(mask))
                        log_debug("XXX" + str(int(mask) & int(destaddr)) + "===" + str(int(prefix)))
                        if matches:
                            next_hop = entry[2]
                            next_name = entry[3]
                            break
                    if next_hop == '':
						for entry in self.forwarding_table:
							prefix = IPv4Address(entry[0])
							mask = IPv4Address(entry[1])
							destaddr = IPv4Address(ip_addr)
							matches = (int(mask) & int(destaddr)) == (int(prefix) & int(mask))
							log_debug("XXX" + str(int(mask) & int(destaddr)) + "===" + str(int(prefix)))
							if matches:
								next_hop = entry[2]
								next_name = entry[3]
								break
                    if next_hop == '':
                        continue
                    elif next_hop == None:
                        next_hop = ipv4.dst 
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
                        #arp_request = create_ip_arp_request(next_mac, next_ip, next_hop)
                        #self.net.send_packet(next_name, arp_request)
                        apr_entry = Apr_queue_entry(pkt, next_hop, next_name, 1, time.time() - 1)
                        self.pkt_queue.put(apr_entry)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

            for i in range(self.pkt_queue.qsize()):
                dequeue_pkt = self.pkt_queue.get()
                if time.time() - dequeue_pkt.timestamp >= 1:
                    if dequeue_pkt.count >= 4:
                            continue
                    dequeue_pkt.count += 1
                    dequeue_ip = self.name_ip_dict[dequeue_pkt.next_name]
                    dequeue_mac = self.mac_ip_dict[dequeue_ip]
                    arp_request = create_ip_arp_request(dequeue_mac, dequeue_ip, dequeue_pkt.next_hop)
                    self.net.send_packet(dequeue_pkt.next_name, arp_request)
                    #log_debug("CCCCCCCCCCCCCCCCCCCCCCCCCCCC SENDING ARP REQUEST FROM QUEUE")
                dequeue_pkt.timestamp = time.time()
                self.pkt_queue.put(dequeue_pkt)

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
