# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
import array

ROUTER_IPADDR1 = "192.168.1.10"
ROUTER_IPADDR2 = "192.168.2.10"
ROUTER_MACADDR1 = "00:00:00:00:00:11"
ROUTER_MACADDR2 = "00:00:00:00:00:22"
ROUTER_PORT1 = 1
ROUTER_PORT2 = 2
PORT_INFO = {}
PORT_INFO[ROUTER_PORT1] = ROUTER_MACADDR1
PORT_INFO[ROUTER_PORT2] = ROUTER_MACADDR2

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arpTable = {}


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

    def handle_arp(self,msg,datapath,packet,etherFrame,inPort):
        arpPacket = packet.get_protocol(arp)
        src_IP = arpPacket.src_ip
        dst_IP = arpPacket.dst_ip
        src = etherFrame.src
        self.arpTable[src_IP] = src
        if arpPacket.opcode == 1:
            # self.logger.debug('received ARP Request %s => %s (port%d)'%(etherFrame.src,etherFrame.dst,inPort))
            if dst_IP == ROUTER_IPADDR1 or dst_IP == ROUTER_IPADDR2:
                self.reply_arp(datapath,etherFrame,arpPacket,dst_IP,inPort)
            else:
                ofproto = datapath.ofproto
                dstMac = "ff:ff:ff:ff:ff:ff"
                outPort = ofproto.OFPP_FLOOD
                self.send_arp(datapath, 1, src, src_IP, dstMac, dst_IP, outPort)
        elif arpPacket.opcode == 2:            
            self.arpTable[src_IP] = src
            self.logger.info(self.arpTable)
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


    def reply_arp(self, datapath, etherFrame, arpPacket, dst_IP, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        self.logger.info(self.arpTable)
        if dst_IP == ROUTER_IPADDR1:
            srcMac = ROUTER_MACADDR1
            outPort = ROUTER_PORT1
        elif dst_IP == ROUTER_IPADDR2:
            srcMac = ROUTER_MACADDR2
            outPort = ROUTER_PORT2
        else:
            self.logger.debug("unknown arp request received !")
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        self.logger.debug("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

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
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]
        #this packet is constructed by tyhe controller, so the in_port is OFPP_CONTROLLER.
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        # self.logger.info("packet in dpid: %s, srce: %s, dest: %s, in_port: %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("ARP src:%s dst:%s", src, dst)
            self.handle_arp(msg,datapath,pkt,eth,in_port)
        #learn mac to ip 
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pak = pkt.get_protocol(ipv4.ipv4)
            icmp_pak = pkt.get_protocol(icmp.icmp)
            dst_ip = ipv4_pak.dst
            src_ip = ipv4_pak.src
            self.logger.info("ICMP src:%s dst:%s src_IP:%s dst_IP:%s", src, dst, src_ip, dst_ip)
            if dst_ip in self.arpTable:
                dst_mac = self.arpTable[dst_ip]
                out_port = self.mac_to_port[dpid][dst_mac]
                actions.append( parser.OFPActionSetField(eth_src=PORT_INFO[out_port]) )
                actions.append( parser.OFPActionSetField(eth_dst=dst_mac) )                
            else:
                srcMac = "00:00:00:00:00:88"
                srcIp = "88.88.88.88"
                dstMac = "ff:ff:ff:ff:ff:ff"
                dstIp = dst_ip
                outPort = ofproto.OFPP_FLOOD
                self.send_arp(datapath, 1, srcMac, srcIp, dstMac, dstIp, outPort)
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