
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet

ROUTER_MACADDR1 = "f2:b5:ed:81:fd:de"
ROUTER_MACADDR2 = "92:39:4f:9c:03:17"

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arpTable = {}#ip to mac
        self.mac_to_port = {1:{'00:00:00:00:00:01':1, '00:00:00:00:00:02':2}}
        self.arpTable['192.168.1.1'] = '00:00:00:00:00:01'
        self.arpTable['192.168.2.2'] = '00:00:00:00:00:02'
        self.logger.info(self.arpTable)

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

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.info('%s'%eth.ethertype)
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        actions = []
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        self.logger.info("packet in dpid: %s, srce: %s, dest: %s, in_port: %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath,pkt,eth,in_port)
        #learn mac to ip 
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            if dst == ROUTER_MACADDR1:
                out_port = 2
                actions.append( parser.OFPActionSetField(eth_src=ROUTER_MACADDR2) )
                actions.append( parser.OFPActionSetField(eth_dst='00:00:00:00:00:02') )

            elif dst == ROUTER_MACADDR2:
                out_port = 1
                actions.append( parser.OFPActionSetField(eth_src=ROUTER_MACADDR1) )
                actions.append( parser.OFPActionSetField(eth_dst='00:00:00:00:00:01') )
            else:
                self.logger.info('Not working')
                return
            actions.append(parser.OFPActionOutput(port=out_port))
            # transfer ICMP packet, in_port = 1 
            out = parser.OFPPacketOut(datapath = datapath,
                                      buffer_id = ofproto.OFP_NO_BUFFER,
                                      in_port = in_port,
                                      actions = actions,
                                      data = msg.data)
            # self.logger.info('packet_out:--> %s'%out)
            datapath.send_msg(out)
    
    def handle_arp(self,datapath,pkt,eth,in_port):
        arpPacket = pkt.get_protocol(arp)
        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            dstIp = arpPacket.src_ip
            srcIp = arpPacket.dst_ip
            dstMac = eth.src
            if arp_dstIp == "192.168.1.10":
                srcMac = ROUTER_MACADDR1
                outPort = 1
            elif arp_dstIp == "192.168.2.10":
                srcMac = ROUTER_MACADDR2
                outPort = 2
            else:
                self.logger.debug("unknown arp request received !")
            self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)  
        elif arpPacket.opcode == 2:
            srcIp = arpPacket.src_ip
            srcMac = eth.src
            self.arpTable[srcIp] = srcMac
            self.logger.info(arpTable)
            return
    
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        #this packet is constructed by tyhe controller, so the in_port is OFPP_CONTROLLER.
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)