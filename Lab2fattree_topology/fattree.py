#!/usr/bin/python

"""
This setup the topology in lab3-part1
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
from mininet.link import Link, Intf, TCLink
import os 
from time import sleep
import sys

class Topology(Topo):
    
    
    def __init__(self):
        "Create Topology."
        
        # Initialize topology
        Topo.__init__(self)
                n = input("Enter a number N for the fat trees: ")
                n = int(n)
                switch = []
                #inner edges
            for i in range(0,n/2):
                  switch.append(self.addSwitch('s'+str(i)))

        #outer edges
        for i in range(n/2,n+n/2):
        switch.append(self.addSwitch('s'+str(i)))

        #hosts
        host = []
        for i in range(0,(n*n/2)):
            host.append(self.addHost('h'+ str(i)))

        #makinglinks
        for i in range(0, n/2):
            for j in range (n/2, n+n/2):
                self.addLink(switch[i], switch[j])
        for i in range (n/2, n+n/2):
            for j in range (0,n/2):
                self.addLink(switch[i], host[-1])
            host.pop()
topos = {'mytopo': (lambda: Topology())}