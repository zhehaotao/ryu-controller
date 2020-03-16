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
        h1 = self.addHost('h1', mac="00:00:00:00:00:11", ip="10.1.1.2/24")
        h2 = self.addHost('h2', mac="00:00:00:00:00:22", ip="10.1.4.2/24")

        self.addLink(h1, s1)
        self.addLink(h2, s1)

if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    CLI(net)

