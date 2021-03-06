from IPy import IP
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
from ryu.topology import event, switches
from ryu.topology.api import *
import array
import networkx as nx

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arpTable = {}
        # 需要配置的交换机端口，set里面存在着port类
        self.gateway = {}
        # 字典类型，port类:人为配置的网关ip
        self.domain = {}
        #字典类型，主机的ip：该主机对应网关的mac
        self.hostIp_to_portMac = {}

        self.topology_api_app = self
        self.network = nx.DiGraph() 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
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

    def handle_arp(self,msg,datapath,packet,etherFrame,inPort):
        arpPacket = packet.get_protocol(arp)
        src_IP = arpPacket.src_ip
        dst_IP = arpPacket.dst_ip
        src = etherFrame.src
        self.arpTable[datapath.id][src_IP] = src
        self.mac_to_port[datapath.id][etherFrame.src] = inPort
        # 如果控制器收到ARP请求，则将模拟网关下发ARP回复
        if arpPacket.opcode == 1:
            # 如果ARP请求的目的ip为网关ip，说明是跨网段通信，由控制器下发ARP回复
            if dst_IP in self.domain.values():
                self.reply_arp(datapath,etherFrame,arpPacket,dst_IP,inPort)
            # 如果ARP请求的目的ip不是网关ip，说明是同网段通信
            else:
                ofproto = datapath.ofproto
                dstMac = "ff:ff:ff:ff:ff:ff"
                outPort = ofproto.OFPP_FLOOD
                self.send_arp(datapath, 1, src, src_IP, dstMac, dst_IP, outPort)
        # 如果控制器收到ARP回复，则将其存入ARP缓存
        elif arpPacket.opcode == 2:
            self.arpTable[datapath.id][src_IP] = src
            # self.logger.info(self.arpTable)
            # 如果ARP回复的目的ip在ARP缓存中，即此目的ip为某一主机的ip
            # 将此ARP回复转发给该主机，以触发ICMP
            if dst_IP in self.arpTable:
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                out_port = self.mac_to_port[datapath.id][etherFrame.dst]
                actions = [parser.OFPActionOutput(port=out_port)]
                in_port = msg.match['in_port']
                out = parser.OFPPacketOut(datapath = datapath,
                                        buffer_id = ofproto.OFP_NO_BUFFER,
                                        in_port = in_port,
                                        actions = actions,
                                        data = msg.data)
                # self.logger.info('packet_out:--> %s'%out)
                datapath.send_msg(out)
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_ARP, eth_dst=etherFrame.dst, eth_src=etherFrame.src)
                self.add_flow(datapath, 1, match, actions)

    def reply_arp(self, datapath, etherFrame, arpPacket, dst_IP, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        # 控制器根据收到ARP请求的网关IP来构造对应ARP回复
        if dst_IP in self.domain.values():
            port = list(self.domain.keys())[list(self.domain.values()).index(dst_IP)]
            srcMac = port.hw_addr
            outPort = port.port_no
        # if dst_IP == ROUTER_IPADDR1:
        #     srcMac = ROUTER_MACADDR1
        #     outPort = ROUTER_PORT1
        # elif dst_IP == ROUTER_IPADDR2:
        #     srcMac = ROUTER_MACADDR2
        #     outPort = ROUTER_PORT2
        else:
            self.logger.debug("unknown arp request received !")
        # 下发ARP回复包
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        # 下发ARP请求包
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        # 下发ARP回复包
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # topo发现主机，及边缘网络的端口，并配置ip
        hosts = get_host(self)
        for host in hosts:
            print(host.to_dict())
            try:                
                host_ip = host.ipv4[0]
            except:
                print ("Please wait for some time")
            else:
                self.hostIp_to_portMac[host_ip] = host.port.hw_addr
                temp = host_ip.split(".")
                gateway_ip = ''
                for i in temp[0:3:1]:
                    gateway_ip += i + '.'
                gateway_ip += '10'
                # self.gateway.add(host.port)
                self.domain[host.port] = gateway_ip

        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.arpTable.setdefault(dpid, {})
        # self.logger.info(self.arpTable)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("ARP src:%s dst:%s", src, dst)
            self.handle_arp(msg,datapath,pkt,eth,in_port)
        #learn mac to ip
        if eth.ethertype == ether_types.ETH_TYPE_IP:   
            self.handle_ip(msg,datapath,pkt,eth,in_port)
            
    def handle_ip(self,msg,datapath,pkt,eth,in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ipv4_pak = pkt.get_protocol(ipv4.ipv4)
        icmp_pak = pkt.get_protocol(icmp.icmp)
        dst = eth.dst
        src = eth.src
        dst_ip = ipv4_pak.dst
        src_ip = ipv4_pak.src
        actions = []
        if IP(src_ip).make_net('255.255.255.0') != IP(dst_ip).make_net('255.255.255.0'):
            src=self.hostIp_to_portMac[src_ip]
            for gateway_ip in self.domain.values():
                if IP(dst_ip).make_net('255.255.255.0') == IP(gateway_ip).make_net('255.255.255.0'):
                    port = list(self.domain.keys())[list(self.domain.values()).index(gateway_ip)]
                    global dst_dpid
                    dst_dpid = port.dpid
                    dst = port.hw_addr
                    out_port = self.get_out_port(datapath,src,dst,in_port)
                    actions = [ofp_parser.OFPActionOutput(out_port)]

                    # if out_port != ofproto.OFPP_FLOOD:
                    #     match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)
                    #     self.add_flow(datapath,1,match,actions)

                    out = ofp_parser.OFPPacketOut(
                            datapath=datapath,buffer_id=msg.buffer_id,in_port=in_port,
                            actions=actions,data=msg.data
                        )

                    datapath.send_msg(out)

            

        # self.logger.info("ICMP src:%s dst:%s src_IP:%s dst_IP:%s", src, dst, src_ip, dst_ip)
        # # 若ARP缓存中存在目的IP，则直接找出目的MAC
        # for gateway_ip in self.domain.values():
        #     if IP(dst_ip).make_net('255.255.255.0') == IP(gateway_ip).make_net('255.255.255.0'):
        #         port = list(self.domain.keys())[list(self.domain.values()).index(gateway_ip)]
        #         dpid = port.dpid

            if dst_ip in self.arpTable[dst_dpid]:
                dst_mac = self.arpTable[dst_dpid][dst_ip]
                out_port = self.mac_to_port[dst_dpid][dst_mac]
                # 如果是跨网段转发，则需重新封装二层源目地址
                if IP(src_ip).make_net('255.255.255.0') != IP(dst_ip).make_net('255.255.255.0'):
                    actions.append( parser.OFPActionSetField(eth_src=self.hostIp_to_portMac[dst_ip]) )
                    actions.append( parser.OFPActionSetField(eth_dst=dst_mac) )
                # 如果不是跨网段转发，则直接转发至相应端口
                actions.append(parser.OFPActionOutput(port=out_port))
                out = parser.OFPPacketOut(datapath = datapath,
                                            buffer_id = ofproto.OFP_NO_BUFFER,
                                            in_port = in_port,
                                            actions = actions,
                                            data = msg.data)
                # self.logger.info('packet_out:--> %s'%out)
                datapath.send_msg(out)
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions)
            # 若ARP缓存中存在目的IP，则以特殊源地址伪造ARP请求
            else:
                srcMac = "00:00:00:00:00:88"
                srcIp = "88.88.88.88"
                dstMac = "ff:ff:ff:ff:ff:ff"
                dstIp = dst_ip
                outPort = ofproto.OFPP_FLOOD
                self.send_arp(datapath, 1, srcMac, srcIp, dstMac, dstIp, outPort)
                        
        # else:
        #     actions.append(parser.OFPActionOutput(port=2))
        #     out = parser.OFPPacketOut(datapath = datapath,
        #                                     buffer_id = ofproto.OFP_NO_BUFFER,
        #                                     in_port = in_port,
        #                                     actions = actions,
        #                                     data = msg.data)
        #     # self.logger.info('packet_out:--> %s'%out)
        #     datapath.send_msg(out)

    # topo discovery
    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])    #event is not from openflow protocol, is come from switchs` state changed, just like: link to controller at the first time or send packet to controller
    def get_topology(self,ev):
        #store nodes info into the Graph
        switch_list = get_switch(self.topology_api_app,None)    #------------need to get info,by debug
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)

        #store links info into the Graph
        link_list = get_link(self.topology_api_app,None)
        #port_no, in_port    ---------------need to debug, get diffirent from  both
        links = [(link.src.dpid,link.dst.dpid,{'attr_dict':{'port':link.dst.port_no}}) for link in link_list]    #add edge, need src,dst,weigtht
        self.network.add_edges_from(links)

        links  = [(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}}) for link in link_list]
        self.network.add_edges_from(links)          

    def get_out_port(self,datapath,src,dst,in_port):
        dpid = datapath.id

        #the first :Doesn`t find src host at graph
        if src not in self.network:
            self.network.add_node(src)
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
            #print("1ooooooooooooooooooo")
            #print(self.network[dpid][next_hop])
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
            #print("2ooooooooooooooooooo")
            #print(out_port)

            #get path info
            #print("6666666666 find dst")
            self.logger.info(self.paths)
            self.logger.info(path)
        else:
            out_port = datapath.ofproto.OFPP_FLOOD    #By flood, to find dst, when dst get packet, dst will send a new back,the graph will record dst info
            #print("8888888888 not find dst")
        return out_port        
