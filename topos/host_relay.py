"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
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
	hR = self.addHost('hR')
	s1 = self.addSwitch('s1')
	s2 = self.addSwitch('s2')
	s3 = self.addSwitch('s3')

        # Add links
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
	self.addLink(s3, h2)

	self.addLink(s1, hR)
	self.addLink(s3, hR)


topos = { 'mytopo': ( lambda: MyTopo() ) }
