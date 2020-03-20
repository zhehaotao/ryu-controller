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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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

    def handle_arp(self,msg,datapath,pkt,eth,in_port):
        arp_packet = pkt.get_protocol(arp)
        src_IP = arp_packet.src_ip
        dst_IP = arp_packet.dst_ip
        src = eth.src
        self.arpTable[src_IP] = src
        self.mac_to_port[datapath.id][eth.src] = in_port
        # 如果控制器收到ARP请求，则将模拟网关下发ARP回复
        if arp_packet.opcode == 1:
            # 如果ARP请求的目的ip为网关ip，说明是跨网段通信，由控制器下发ARP回复
            if dst_IP in self.domain.values():
                self.reply_arp(datapath,eth,arp_packet,dst_IP,in_port)
            # 如果ARP请求的目的ip不是网关ip，说明是同网段通信
            else:
                ofproto = datapath.ofproto
                dstMac = "ff:ff:ff:ff:ff:ff"
                outPort = ofproto.OFPP_FLOOD
                self.send_arp(datapath, 1, src, src_IP, dstMac, dst_IP, outPort)
        # 如果控制器收到ARP回复，则将其存入ARP缓存
        elif arp_packet.opcode == 2:
            self.arpTable[src_IP] = src
            # self.logger.info(self.arpTable)
            # 如果ARP回复的目的ip在ARP缓存中，即此目的ip为某一主机的ip
            # 将此ARP回复转发给该主机，以触发ICMP
            if dst_IP in self.arpTable:
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                out_port = self.mac_to_port[datapath.id][eth.dst]
                actions = [parser.OFPActionOutput(port=out_port)]
                in_port = msg.match['in_port']
                out = parser.OFPPacketOut(datapath = datapath,
                                        buffer_id = ofproto.OFP_NO_BUFFER,
                                        in_port = in_port,
                                        actions = actions,
                                        data = msg.data)
                # self.logger.info('packet_out:--> %s'%out)
                datapath.send_msg(out)
                match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_ARP, eth_dst=eth.dst, eth_src=eth.src)
                self.add_flow(datapath, 1, match, actions)

    def reply_arp(self, datapath, eth, arp_packet, dst_IP, in_port):
        dstIp = arp_packet.src_ip
        srcIp = arp_packet.dst_ip
        dstMac = eth.src
        # 控制器根据收到ARP请求的网关IP来构造对应ARP回复
        if dst_IP in self.domain.values():
            port = list(self.domain.keys())[list(self.domain.values()).index(dst_IP)]
            srcMac = port.hw_addr
            outPort = port.port_no
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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        actions = []
        self.mac_to_port.setdefault(dpid, {})
        # self.logger.info(self.arpTable)
        # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #     # ignore lldp packet
        #     return
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("ARP src:%s dst:%s", src, dst)
            self.handle_arp(msg,datapath,pkt,eth,in_port)
        #learn mac to ip
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(msg,datapath,pkt,eth,in_port)            
            
        # topo发现主机，及边缘网络的端口，并配置ip
        hosts = get_host(self)
        for host in hosts:
            # print(host.to_dict())
            try:                
                host_ip = host.ipv4[0]
            except:
                pass
                # print ("Controller is finding host")
            else:
                self.hostIp_to_portMac[host_ip] = host.port.hw_addr
                temp = host_ip.split(".")
                gateway_ip = ''
                for i in temp[0:3:1]:
                    gateway_ip += i + '.'
                gateway_ip += '10'
                # self.gateway.add(host.port)
                self.domain[host.port] = gateway_ip
    
    def handle_ip(self,msg,datapath,pkt,eth,in_port):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ipv4_pak = pkt.get_protocol(ipv4.ipv4)
        icmp_pak = pkt.get_protocol(icmp.icmp)
        dst = eth.dst
        src = eth.src
        dst_ip = ipv4_pak.dst
        src_ip = ipv4_pak.src
        actions = []
        # 若ARP缓存中存在目的IP，则直接找出目的MAC
        if dst_ip in self.arpTable:
            dst_mac = self.arpTable[dst_ip]
            out_port = self.mac_to_port[dpid][dst_mac]
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
            return