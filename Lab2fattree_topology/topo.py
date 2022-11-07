from mininet.topo import Topo


class Topology(Topo):
    
    
    def __init__(self):
        "Create Topology."
        
        # Initialize topology
        Topo.__init__(self)
        
        
        #### There is a rule of naming the hosts and switch, so please follow the rules like "h1", "h2" or "s1", "s2" for hosts and switches!!!!
      
        # Add hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        
        # Add switches
        swA = self.addSwitch('s1')
        swB = self.addSwitch('s2')
        swC = self.addSwitch('s3')
        swD = self.addSwitch('s4')
        swE = self.addSwitch('s5')

        self.addLink(host1, swA, 1, 1)
        self.addLink(host2, swD, 2, 2)
        self.addLink(swA, swB, 2, 1)    # Connect port 1 of switch A with port 2 of switch B
        self.addLink(swB, swD, 2, 1)
        self.addLink(swB, swE, 3, 2)
        self.addLink(swA, swC, 3, 1)
        self.addLink(swC, swE, 2, 3)
        self.addLink(swD, swE, 3, 1)
        self.addLink(swC, swD, 3, 4)




# This is for "mn --custom"
topos = { 'mytopo': ( lambda: Topology() ) }