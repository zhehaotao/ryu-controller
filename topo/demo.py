#!/usr/bin/python2

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController

class SingleSwitchTopo(Topo):
    "Single switch connected to 2 hosts in the same network."
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', mac="00:00:00:00:00:01")
        h2 = self.addHost('h2', mac="00:00:00:00:00:02")

        self.addLink(h1, s1)
        self.addLink(h2, s1)

if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    net.get('h1').cmd('ifconfig h1-eth0 192.168.1.1 netmask 255.255.255.0')
    net.get('h2').cmd('ifconfig h2-eth0 192.168.2.2 netmask 255.255.255.0')
    net.get('h1').cmd('route add default gw 192.168.1.10')
    net.get('h2').cmd('route add default gw 192.168.2.10')
    CLI(net)

