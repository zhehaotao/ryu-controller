from IPy import IP

from ryu.lib.packet import *
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

SWITCH_ETH1 = '192.168.1.10'
SWITCH_ETH2 = '192.168.2.10'

class PingResponder(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self,*args,**kwargs):
        super(PingResponder, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def _switch_features_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,priority=0,match=parser.OFPMatch(),instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self,ev):
        self.mac_to_port = {1:{'00.00.00.00.00.01':1, '00.00.00.00.00.02':2}}
        self.arp_table['192.168.1.1'] = '00.00.00.00.00.01'
        self.arp_table['192.168.2.2'] = '00.00.00.00.00.02'
        self.logger.info(arp_table)
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        self.logger.info("---------------------")
        self.logger.info("Receive Packet-in from %d",datapath.id)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            src_ip = pkt_arp.src_ip
            dst_ip = pkt_arp.dst_ip
            # if dst_ip == '88.88.88.88':
            #     self.mac_to_port[dpid][src] = pozrt
            #     self.logger.info("Special")
            #     return
            self.logger.info("src: %s, dst: %s", src_ip, dst_ip)
            if IP(src_ip).make_net('255.255.255.0') == IP(dst_ip).make_net('255.255.255.0'):
                self._handle_normal_pkt_(msg, pkt_ethernet)
                return
            if IP(src_ip).make_net('255.255.255.0') != IP(dst_ip).make_net('255.255.255.0'):
                self.logger.info('diff')
                self._handle_arp(msg, pkt_ethernet, pkt_arp)
                return
        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_IP:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            pkt_icmp = pkt.get_protocol(icmp.icmp)
            src_ip = pkt_ipv4.src_ip
            dst_ip = pkt_ipv4.dst_ip
            if dst_ip in self.arp_table:
                dst_mac = self.arp_table[dst_ip]
                actions.append( parser.OFPActionSetField(eth_dst=dst_mac) )
                out_port = self.mac_to_port[dpid][dst]
                actions.append(parser.OFPActionOutput(port=out_port))
                out = parser.OFPPacketOut(datapath = datapath,
                                        buffer_id = ofproto.OFP_NO_BUFFER,
                                        in_port = port,
                                        actions = actions,
                                        data = msg.data)
                datapath.send_msg(out)

    
    def _handle_normal_pkt_(self, msg, pkt_ethernet):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] 
        dst = pkt_ethernet.dst
        src = pkt_ethernet.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_arp(self, msg, pkt_ethernet, pkt_arp):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] 
        dst_ip = pkt_arp.dst_ip
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if dst_ip in arp_table:
            target_mac = arp_table[dst_ip]
        actions = []
        # eth_src is the mac of s1-eth2, assume it is already known.
        actions.append( parser.OFPActionSetField(eth_src='00.00.00.88.88.88') )
        actions.append( parser.OFPActionSetField(eth_dst=target_mac) )  
        # pkt = packet.Packet()
        # pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst='FF:FF:FF:FF:FF:FF',src='00.00.00.00.00.88'))
        # pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,src_mac='00.00.00.00.00.88',src_ip='88.88.88.88',dst_mac='00.00.00.00.00.00',dst_ip=dst_ip))
        # data = pkt.data
        # actions = [parser.OFPActionOutput(port=port)]
        # out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
        actions.append(parser.OFPActionOutput(port=2))
        out = parser.OFPPacketOut(datapath = datapath,
                                      buffer_id = ofproto.OFP_NO_BUFFER,
                                      in_port = in_port,
                                      actions = actions,
                                      data = msg.data)
        datapath.send_msg(out)




