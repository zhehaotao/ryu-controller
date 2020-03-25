from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.lib.packet import packet,ethernet,ether_types,ipv4
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet
from ryu.topology import event
from ryu.topology.api import get_switch,get_link
from ryu.ofproto import ofproto_v1_3

import networkx as nx

from IPy import IP

GATEWAY_IP = {1:['192.168.1.10'], 2:['192.168.2.10'],3:['192.168.3.10','192.168.4.10']}

class MyShortestForwarding(app_manager.RyuApp):
    '''
    class to achive shortest path to forward, based on minimum hop count
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(MyShortestForwarding,self).__init__(*args,**kwargs)

        #set data structor for topo construction
        self.network = nx.DiGraph()        #store the dj graph
        self.paths = {}        #store the shortest path
        self.topology_api_app = self
        self.switches = {}
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        '''
        manage the initial link between switch and controller
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        match = ofp_parser.OFPMatch()    #for all packet first arrive, match it successful, send it ro controller
        actions  = [ofp_parser.OFPActionOutput(
                            ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER
                            )]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self,datapath,priority,match,actions):
        '''
        fulfil the function to add flow entry to switch
        '''
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        mod = ofp_parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,instructions=inst)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        '''
        manage the packet which comes from switch
        '''
        #first get event infomation
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        dpid = datapath.id

        #second get ethernet protocol message
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        src = eth_pkt.src     #note: mac info willn`t  change in network
        dst = eth_pkt.dst
        out_port = datapath.ofproto.OFPP_FLOOD

        if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp)
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.arp_table[src_ip] = src
            for arr in GATEWAY_IP.values():
                if dst_ip in arr:
                    self.reply_arp(datapath,eth_pkt,arp_pkt,src,in_port)
                    return
            if dst_ip == '88.88.88.88':
                self.arp_table[src_ip] = src
                self.network.add_node(src)
                # switch和主机之间的链路及switch转发端口
                self.network.add_edge(dpid, src, attr_dict={'port':in_port})
                self.network.add_edge(src, dpid)
                self.paths.setdefault(src, {})

        if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
            # self.handle_ip(msg,datapath,pkt,eth,in_port)
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            dst_ip = ipv4_pkt.dst
            src_ip = ipv4_pkt.src
            for ele in GATEWAY_IP[dpid]:
                if IP(dst_ip).make_net('255.255.255.0') == IP(ele).make_net('255.255.255.0'):
                    if dst_ip not in self.arp_table:
                        src = "00:00:00:00:00:88"
                        src_ip = "88.88.88.88"
                        dst = "ff:ff:ff:ff:ff:ff"
                        out_port = ofproto.OFPP_FLOOD
                        self.send_arp(datapath, 1, src, src_ip, dst, dst_ip, out_port)
                        return
                    else:
                        dst = self.arp_table[dst_ip]
                        out_port = datapath.ofproto.OFPP_FLOOD
                        actions = [ofp_parser.OFPActionSetField(eth_dst=dst)]
                        actions.append(ofp_parser.OFPActionOutput(out_port))
                        out = ofp_parser.OFPPacketOut(
                                    datapath=datapath,buffer_id=msg.buffer_id,in_port=in_port,
                                    actions=actions,data=msg.data)
                        datapath.send_msg(out)
                        return
                else:
                    out_port = datapath.ofproto.OFPP_FLOOD

        # out_port = self.get_out_port(datapath,src,dst,in_port)
        actions = [ofp_parser.OFPActionOutput(out_port)]

        # if out_port != ofproto.OFPP_FLOOD:
        #     match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=dst)
        #     self.add_flow(datapath,1,match,actions)

        out = ofp_parser.OFPPacketOut(
                datapath=datapath,buffer_id=msg.buffer_id,in_port=in_port,
                actions=actions,data=msg.data
        )

        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])    #event is not from openflow protocol, is come from switchs` state changed, just like: link to controller at the first time or send packet to controller
    def get_topology(self,ev):
        '''
        get network topo construction, save info in the dict
        '''

        #store nodes info into the Graph
        switch_list = get_switch(self.topology_api_app,None)    #------------need to get info,by debug
        for switch in switch_list:
            self.switches.setdefault(switch.dp.id, {})
            for port in switch.ports:
                self.switches[switch.dp.id][port.port_no] = port.hw_addr
        print (self.switches)
        # switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(self.switches)
        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'attr_dict':{'port':link.src.port_no}}) for link in links_list]
        print (links)
        self.network.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}}) for link in links_list]
        print (links)
        self.network.add_edges_from(links)
        print (self.network.edges())

    def get_out_port(self,datapath,src,dst,in_port):
        '''
        datapath: is current datapath info
        src,dst: both are the host info
        in_port: is current datapath in_port
        '''
        dpid = datapath.id

        #the first :Doesn`t find src host at graph
        if src not in self.network:
            self.network.add_node(src)
            # switch和主机之间的链路及switch转发端口
            self.network.add_edge(dpid, src, attr_dict={'port':in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})

        #second: search the shortest path, from src to dst host
        if dst in self.network:
            if dst not in self.paths[src]:    #if not cache src to dst path,then to find it
                path = nx.shortest_path(self.network,src,dst)
                self.paths[src][dst]=path

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid)+1]
            # switch和主机之间的端口也能找到
            out_port = self.network[dpid][next_hop]['attr_dict']['port']

        else:
            out_port = datapath.ofproto.OFPP_FLOOD    #By flood, to find dst, when dst get packet, dst will send a new back,the graph will record dst info
        print("paths: ",self.paths)
        return out_port

    
    def reply_arp(self, datapath, eth_pkt, arp_pkt, src, in_port):
        dpid = datapath.id
        if src not in self.network:
            self.network.add_node(src)
            # switch和主机之间的链路及switch转发端口
            self.network.add_edge(dpid, src, attr_dict={'port':in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})
        reply_dst_ip = arp_pkt.src_ip
        reply_src_ip = arp_pkt.dst_ip
        reply_dst_mac = eth_pkt.src
        reply_src_mac = self.switches[dpid][in_port]
        out_port = in_port
        self.send_arp(datapath, 2, reply_src_mac, reply_src_ip, reply_dst_mac, reply_dst_ip, out_port)

    def send_arp(self, datapath, opcode, src, src_ip, dst, dst_ip, out_port):
        # 下发ARP请求包
        if opcode == 1:
            target_mac = "00:00:00:00:00:00"
            target_ip = dst_ip
        # 下发ARP回复包
        elif opcode == 2:
            target_mac = dst
            target_ip = dst_ip
        e = ethernet.ethernet(dst, src, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, src, src_ip, target_mac, target_ip)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
