# TopoGuard++ (TopoDucken)

An extension of the TopoGuard+ security add-on for Floodlight SDN controller.

(Fork of https://github.com/xuraylei/TopoGuard_Plus)

Project proposal link: https://drive.google.com/file/d/1cxq5LbFKMqVhgwjrmpfcsju7tLnOCpeq/view?usp=sharing


## Build Instructions

### Starting Floodlight and Mininet

- Build and run Floodlight via ```ant run```, 
- Wait for the Debug Server to finish launching
- Run mininet (e.g. ```sudo mn --custom topos/host_relay.py --topo mytopo --mac --controller remote```)
- Wait for all switches to connect
- From the mininet controller, run ```pingall``` to give all hosts an IP address

### Host Relay
- From the mininet controller, run ```xterm hR``` to open a terminal for the hostRelay
- Navigate to topo_plusplus/scripts
- From hR's xterm, run ```bridge.sh``` (or 'sudo bridge.sh')

### Denial of Service Attack
*Note: hR must have already have run bridge.sh for this step*
- From the mininet controller, run ```xterm hR``` to open a terminal for the hostRelay
- Navigate to topo_plusplus/scripts
- From hR's xterm, run ```dos.sh```
