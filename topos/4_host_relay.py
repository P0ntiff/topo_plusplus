"""


   h1 --- s1 --- s2 --- s3 --- h2
   	   |             |
   h3 --- s4 -- s5 s6 -- s7 --- h4
		|   |
		HOSTR
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
	h1 = self.addHost('h1')
	h2 = self.addHost('h2')
	h3 = self.addHost('h3')
	h4 = self.addHost('h4')
	hR = self.addHost('hR') #H5 is the host relay, between S5 and S6

	s1 = self.addSwitch('s1')
	s2 = self.addSwitch('s2')
	s3 = self.addSwitch('s3')
	s4 = self.addSwitch('s4')
	s5 = self.addSwitch('s5')
	s6 = self.addSwitch('s6')
	s7 = self.addSwitch('s7')

        # Add links
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
	self.addLink(s3, h2)

	self.addLink(s1, s4)
	self.addLink(s3, s7)

        self.addLink(h3, s4)
        self.addLink(s4, s5)
        self.addLink(s6, s7)
        self.addLink(s7, h4)

	#HOST RELAY
        self.addLink(hR, s5)
	self.addLink(hR, s6)


topos = { 'mytopo': ( lambda: MyTopo() ) }
