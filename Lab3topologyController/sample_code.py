from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.ip2mac = {
                '10.0.0.1': '10:00:00:00:00:01',
                '10.0.0.2': '10:00:00:00:00:02',
                '10.0.0.3': '10:00:00:00:00:03',
                '10.0.0.4': '10:00:00:00:00:04'
        }

    def clockwise_outport(self, dpid, src, dst):
            if (dpid == 1 and dst == '10:00:00:00:00:01') \
                    or (dpid == 2 and dst == '10:00:00:00:00:02') \
                    or (dpid == 3 and dst == '10:00:00:00:00:03') \
                    or (dpid == 4 and dst == '10:00:00:00:00:04'):
                return 1
            return 2

    def couter_clockwise_outport(self, dpid, src, dst):
            if (dpid == 1 and dst == '10:00:00:00:00:01') \
                    or (dpid == 2 and dst == '10:00:00:00:00:02') \
                    or (dpid == 3 and dst == '10:00:00:00:00:03') \
                    or (dpid == 4 and dst == '10:00:00:00:00:04'):
                return 1
            return 3

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)

        #####
        pkt_arp = pkt.get_protocal(arp.arp)
        pkt_ipv4 = pkt.get_protocal(ipv4.ipv4)
        pkt_icmp = pkt.get_protocal(icmp.icmp)
        pkt_tcp = pkt.get_protocal(tcp.tcp)
        pkt_udp = pkt.get_protocal(udp.udp)

        if dst.split(":")[0] != '33' and not pkt_arp:
            # don't print multicast
            # don't print arp
            print("[controller]sw:", dpid, "in:", in_port) 
            print("" * 8, pkt)

        # ARP
        if pkt_arp:
            print("[ARP]", dpid, src, dst, " IP", pkt_arp.dst_ip)
            mypkt = packet.Packet()
            mypkt.add_protocol(ethernet.ethernet(
            ethertype=0x0806,  
            src=self.ip2mac[pkt_arp.dst_ip],  # need to know the ip asked
            dst=src  # eth src
            ))

            mypkt.add_protpcal(arp.arp(
            dst_mac = pkt_arp.src_mac,
            dst_ip = pkt_arp.src_ip,
            opcode = arp.ARP_REPLY,
            src_mac = self.ip2mac[pkt_arp.dst_ip],
            src_ip = pkt_arp.dst_ip
            ))
            self._send_packet(datapath, in_port, mypkt)


        # IPV4
        elif pkt_ipv4:
            # ICMP
            if pkt_icmp:
                print('[ICMP]', dpid, src, dst)
                out_port = self.clockwise_outport(
                    dpid, src, dst) #clockwise
                match = parser.OFPMatch(ether_type = 0x0800,
                                        eth_dst = dst)
                actions = [parser.OFPActionOutput(port = out_port)]
                self.add_flow(datapath, 1, match, actions)
                self._send_packet(datapath, out_port, pkt)

            # TCP
            elif pkt_tcp:
                print('[TCP]')
                if pkt_tcp.dst_port == 8080 and (
                    src == '10:00:00:00:00:02' or src == 
                    '10:00:00:00:00:04'):
                    print(" [HTTP][TCP][H2/H4]")
                    mypkt = packet.Packet()
                    mypkt.add_protocol(
                        ethernet.ethernet(
                            ethertype = eth.ethertype,
                            src = dst,
                            dst = src
                        ))
                    mypkt.add_protpcal(
                        ipv4.ipv4(
                            src = pkt_ipv4.dst,
                            dst = pkt_ipv4.src,
                            proto = 6
                        ))
                    mypkt.add_protpcal(tcp.tcp(src_port = pkt_tcp.dst_port,
                                                dst_port = pkt_tcp.src_port,
                                                ack = pkt_tcp.seq + 1,
                                                bits = 0b010100
                                                ))
                    # send packet
                    self._send_packet(datapath, 1, mypkt)

                    print('     [finish h2 / h4 of http]')

                    # add flow, ask controller
                    match = parser.OFPMatch(eth_type = 0x0800, # ip
                                            ip_proto = 6,   # tcp
                                            eth_src = src,
                                            tcp_dst = pkt_tcp.dst_port)

                    actions = [
                        parser.OFActionOutput(
                            ofproto.OFPP_CONTROLLER,
                            ofproto.OFPCML_NO_BUFFER
                        )]
                    self.add_flow(datapath, 100, match, actions)

                    # non-http tco
                    # go clockwise
                else:
                    # cal out port
                    print(
                        '   [normal TCP]',
                        dpid,
                        src,
                        dst,
                        "tcp_dst:",
                        pkt_tcp.dst_port,
                        "tcp_src:",
                        pkt_tcp.src_port)
                    out_port = self.clockwise_outport(
                        dpid, src, dst  # icmp go clockwise
                    )
                    # pattern for match
                    match = parser.OFPMatch(eth_type = 0x0800, # ip
                                            ip_proto = 6, # tcp
                                            eth_src = src,
                                            eth_dst = dst,
                                            tcp_dst = pkt_tcp.dst_port)
                    
                    # action to do
                    actions = [parser.OFPActionOutput(port = out_port)]

                    # add flow
                    self.add_flow(datapath, 1, match, actions)

                    # send packet
                    self._send_packet(datapath, out_port, pkt)

            # UDP
            elif pkt_udp:
                print(' [UDP] ')

                # ip protocal 17 for udp

                if src != '10:00:00:00:00:01' and src != '10:00:00:00:00:04':
                    # go counter - clockwise
                    # cal out port
                    print(
                        '   [normal UDP]',
                        dpid,
                        src,
                        dst,
                        "tcp_dst:",
                        pkt_udp.dst_port,
                        "tcp_src:",
                        pkt_udp.src_port)
                    out_port = self.counter_clockwise_outport(
                        dpid, src, dst)     # icmp gp clockwise
                    # pattern for match
                    match = parser.OFPMatch(eth_type = 0x0800, # ip
                                            ip_proto = 17,  # udp
                                            eth_src = src,
                                            eth_dst = dst,
                                            udp_dst = pkt_udp.dst_port)
                    
                    # action to do
                    actions = [parser.OFActionOutput(port = out_port)]

                    # add flow
                    self.add_flow(datapath, 1, match, actions)

                    # send packet
                    self._send_packet(datapath, out_port, pkt)

                else:
                    # if host1 or host4 drop
                    print("[UDP] to drop")

                    match = parser.OFPMatch(eth_type = 0x0800, # IP
                                            ip_proto = 17, # udp
                                            eth_src = src,
                                            eth_dst = dst,
                                            udp_dst = pkt_udp.dst_port)

                    # action to do
                    actions = []    # drop
                    # add flow
                    self.add_flow(datapath, 10, match, actions)
                    # not send packet

            else:
                print("[ELSE]")
                print(pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()

        data = pkt.data
        actions = [parser.OFPActionOutput(port = port)]
        print(" sw:", datapath.id, "out:", port)
        print()
        out = parser.OFPPacketOut(datapath = datapath,
                                 buffer_id = ofproto.OFP_NO_BUFFER,
                                 in_port = ofproto.OFPP_CONTROLLER,
                                 actions = actions,
                                 data = data)        
        datapath.send_msg(out)


        