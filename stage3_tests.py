import struct

from dynamicroutingmessage import DynamicRoutingMessage
from ipaddress import IPv4Address
from switchyard.lib.userlib import *
from switchyard.lib.packet import *


def mk_dynamic_routing_packet(ethdst, advertised_prefix, advertised_mask,
                               next_hop):
    drm = DynamicRoutingMessage(advertised_prefix, advertised_mask, next_hop)
    Ethernet.add_next_header_class(EtherType.SLOW, DynamicRoutingMessage)
    pkt = Ethernet(src='00:00:22:22:44:44', dst=ethdst,
                   ethertype=EtherType.SLOW) + drm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl = 64):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=ttl)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def router_tests():
    s = TestScenario("Basic functionality testing for DynamicRoutingMessage")

    # Initialize switch with 3 ports.
    s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
    s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')

    # 1   IP packet to be forwarded to 172.16.42.2 should arrive on
    #     router-eth0
    #         Expected event: recv_packet Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) on router-eth0

    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    # 2   Router should send ARP request for 172.16.42.2 out router-
    #     eth2 interface
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->ff:ff:ff:ff:ff:ff ARP | Arp
    #         10:00:00:00:00:03:172.16.42.1 ff:ff:ff:ff:ff:ff:172.16.42.2
    #         out router-eth2

    arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

    # 3   Router should receive ARP response for 172.16.42.2 on
    #     router-eth2 interface
    #         Expected event: recv_packet Ethernet
    #         30:00:00:00:00:01->10:00:00:00:00:03 ARP | Arp
    #         30:00:00:00:00:01:172.16.42.2 10:00:00:00:00:03:172.16.42.1
    #         on router-eth2

    arp_response = create_ip_arp_reply('30:00:00:00:00:01', '10:00:00:00:00:03',
                                       '172.16.42.2', '172.16.42.1')
    s.expect(PacketInputEvent("router-eth2", arp_response), "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")


    # 4   IP packet should be forwarded to 172.16.42.2 out router-eth2
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) out router-eth2

    packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
    s.expect(PacketOutputEvent("router-eth2", packet), "IP packet should be forwarded to 172.16.42.2 out router-eth2")
	# 5. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:01',
                                        IPv4Address('172.0.0.0'),
                                        IPv4Address('255.255.0.0'),
                                        IPv4Address('192.168.1.8'))
    s.expect(PacketInputEvent("router-eth0", drm_pkt),
             "Dynamic routing message on eth0")
	
	# 6. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:03',
                                        IPv4Address('172.0.0.0'),
                                        IPv4Address('255.255.255.0'),
                                        IPv4Address('192.168.1.255'))
    s.expect(PacketInputEvent("router-eth2", drm_pkt),
             "Dynamic routing message on eth2")

	# 7. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:02',
                                        IPv4Address('172.0.0.0'),
                                        IPv4Address('255.255.128.0'),
                                        IPv4Address('192.168.1.128'))
    s.expect(PacketInputEvent("router-eth0", drm_pkt),
             "Dynamic routing message on eth0")

	# 8. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:01',
                                        IPv4Address('172.0.0.0'),
                                        IPv4Address('255.255.255.0'),
                                        IPv4Address('192.168.1.254'))
    s.expect(PacketInputEvent("router-eth0", drm_pkt),
             "Dynamic routing message on eth0")

    # 9. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:01',
                                        IPv4Address('172.0.0.0'),
                                        IPv4Address('255.255.192.0'),
                                        IPv4Address('192.168.1.192'))
    s.expect(PacketInputEvent("router-eth0", drm_pkt),
             "Dynamic routing message on eth0")

	# 10. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:01',
                                        IPv4Address('172.0.0.0'),
                                        IPv4Address('255.255.255.128'),
                                        IPv4Address('192.168.1.128'))
    s.expect(PacketInputEvent("router-eth0", drm_pkt),
             "Dynamic routing message on eth0")

	# 11. Dynamic message received
    drm_pkt = mk_dynamic_routing_packet('10:00:00:00:00:02',
                                        IPv4Address('172.16.0.0'),
                                        IPv4Address('255.255.0.0'),
                                        IPv4Address('192.168.1.4'))
    s.expect(PacketInputEvent("router-eth1", drm_pkt),
             "Dynamic routing message on eth1")

	# 12. Receive IP message from eth2 to 172.16.00.00
    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.0', ipdst = '172.16.0.0')
    s.expect(PacketInputEvent("router-eth2", packet), "IP packet to be forwarded to 172.16.0.0 should arrive on router-eth2")

	# 18. Send ARP request for 192.168.1.4
    arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '192.168.1.4')
    s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 192.168.1.4 out router-eth1 interface")
	
    s.expect(PacketInputTimeoutEvent(2), "Waiting 1 seconds")

	# 18. Send ARP request for 192.168.1.4
    arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '192.168.1.4')
    s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 192.168.1.4 out router-eth1 interface")

    # 13. Receive IP message from eth2 to 172.00.00.00
    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.11', ipdst = '172.0.0.0')
    s.expect(PacketInputEvent("router-eth1", packet), "IP packet to be forwarded to 192.168.1.128 should arrive on router-eth2")

	# 16. Send ARP request for 192.168.1.128
    arp_request  = create_ip_arp_request('10:00:00:00:00:01', '192.168.1.1', '192.168.1.128')
    s.expect(PacketOutputEvent("router-eth0", arp_request), "Router should send ARP request for 192.168.1.128 out router-eth0 interface")

	    # 3   Router should receive ARP response for 172.16.42.2 on
    #     router-eth2 interface
    #         Expected event: recv_packet Ethernet
    #         30:00:00:00:00:01->10:00:00:00:00:03 ARP | Arp
    #         30:00:00:00:00:01:172.16.42.2 10:00:00:00:00:03:172.16.42.1
    #         on router-eth2

    arp_response = create_ip_arp_reply('30:00:00:00:00:04', '10:00:00:00:00:01',
                                       '192.168.1.128', '192.168.1.1')
    s.expect(PacketInputEvent("router-eth0", arp_response), "Router should receive ARP response on router-eth0 interface")
   
    packet = mk_pkt(hwsrc='10:00:00:00:00:01', hwdst='30:00:00:00:00:04', ipsrc='192.168.1.11', ipdst='172.0.0.0', ttl=63)
    s.expect(PacketOutputEvent("router-eth0", packet), "IP packet should be forwarded out router-eth0")

    s.expect(PacketInputTimeoutEvent(2), "Waiting 1 seconds")

	# 15. Send ARP request for 192.168.1.4
    arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '192.168.1.4')
    s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 192.168.1.4 out router-eth1 interface")

	# 14. Receive IP message from eth2 to 172.18.128.0
    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.18.64.0', ttl = 64)
    s.expect(PacketInputEvent("router-eth2", packet), "IP packet to be forwarded to 172.16.64.0 should leave on router-eth2")

	# 17. Send ARP request for 10.10.1.254
    arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.1.254')
    s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 10.10.1.254 out router-eth1 interface")

    s.expect(PacketInputTimeoutEvent(2), "Waiting 1 seconds")

	# 20. Send ARP request for 10.10.1.254
    arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.1.254')
    s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 192.168.1.4 out router-eth1 interface")
    
    arp_response = create_ip_arp_reply('30:00:00:00:00:06', '10:00:00:00:00:02',
                                       '10.10.1.254', '10.10.0.1')
    s.expect(PacketInputEvent("router-eth1", arp_response), "Router should receive ARP response on router-eth1 interface")
   
    packet = mk_pkt(hwsrc = '10:00:00:00:00:02', hwdst =  '30:00:00:00:00:06', ipsrc  = '192.168.1.100', ipdst = '172.18.64.0', ttl = 63)
    s.expect(PacketOutputEvent("router-eth1", packet), "IP packet  should leave on router-eth1")


	# 24. Timeout after dropping queue
    s.expect(PacketInputTimeoutEvent(3), "Waiting 2 seconds")
    # After the above dynamic routing packet has been received your forwarding table should get updated.
    # After this if another packet is received with its prefix in the same network as both static and dynamic routes,
    # the dynamic one gets chosen.

    # TODO for students: Write your own test for the above mentioned comment. This is not a deliverable. But will help
    #  you test if your code is correct or not.

    return s

scenario = router_tests()
