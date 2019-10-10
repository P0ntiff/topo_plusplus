package net.floodlightcontroller.linkverifier;

import java.io.IOException;
import java.util.*;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;
import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;

import net.floodlightcontroller.linkverifier.web.LinkVerifierWebRoutable;

/*
 * TOPOGUARD++ CLASS FOR VERIFICATION OF FLOW BETWEEN LINKS
 */
public class LinkVerifier implements IOFMessageListener, IFloodlightModule<IFloodlightService> {

	// Instance Variables
	protected IRestApiService restApi;
	protected IFloodlightProviderService floodlightProvider;
	protected IRoutingService routingEngine;
	protected ILinkDiscoveryService linkEngine;
	protected IDeviceService deviceEngine;
	protected static Logger log;
	public static final String MODULE_NAME = "linkverifier";


	private Random rand;


	private Map<NodePortTuple, Link> linkMap = new HashMap<>(); //Key = NodePortTuple, Value=Link
	private Map<String, IDevice> deviceMap = new HashMap<>(); //Key =HostIP , Value= AttachmentPoints
	private Map<Integer, String[]> packetMap = new HashMap<>(); //Key = PacketId, Value = {time, srcSw, dstSw}

	private StatisticsManager statManager;
	private HiddenPacketWorker hpvWorker;


	private enum GetterType {
		DEVICES,
		ROUTES,
		LINKS,
	}

//- - -

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		if(msg.getType().equals(OFType.PACKET_IN)) {
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

			if(eth.getPayload() instanceof IPv4) {

				IPv4 packet = (IPv4) eth.getPayload();
				//if the pkt hash is in the system, and this is the expected switch for it

				//log.info("Received {} from {}", packet.hashCode(), sw.getStringId());
				if(packetMap.containsKey(packet.hashCode())) {

					String[] info = packetMap.get(packet.hashCode());
					if(sw.getStringId().equals(info[0])) {
						log.warn("HPV: A hidden packet ({}) has been returned from {}", packet.hashCode(), sw.getStringId());
						packetMap.remove(packet.hashCode());
						return Command.STOP; //gobble up hidden packet
					}

					log.info("HPV: Hidden packet ({}) returned from incorrect switch {} (ignoring it)", packet.hashCode(), sw.getStringId());

				} else {
					return Command.CONTINUE; //not a HP, so process normally
				}

			}
		}
		return Command.CONTINUE;
	}


	//***************
	// HIDDEN PACKET METHODS
	//***************


	/**
	 * Randomly selects two different host IP addresses from the DeviceMap
	 * @return String[] two host IP addresses
	 */
	public String[] get_random_host_addr(){
		Object[] addrs = deviceMap.keySet().toArray();
		if (addrs.length < 2) return null; // only 0 or 1 hosts in the system.

		Object IP1, IP2;

		do {
			IP1 = addrs[rand.nextInt(addrs.length)];
			IP2 = addrs[rand.nextInt(addrs.length)];
		} while (IP1.equals(IP2));

		String[] result = {IP1.toString(), IP2.toString()};
		return result;
	}

	public Route get_route(SwitchPort startPoint, SwitchPort endPoint){
		log.info("Getting route information...");
		Route route =
				routingEngine.getRoute(startPoint.getSwitchDPID(),
						(short) startPoint.getPort(),
						endPoint.getSwitchDPID(),
						(short) endPoint.getPort(), 0); //cookie = 0, i.e., default route
		return route;
	}

	public void get_host_devices(){
		deviceMap.clear();
		for(IDevice d : deviceEngine.getAllDevices()){
			Integer[] addrs = d.getIPv4Addresses();
			if(addrs.length == 0) continue;
			deviceMap.put(IPv4.fromIPv4Address(addrs[0]), d);
		}
		log.info("{} devices in map...", deviceMap.size());
	}

	public void print_route(List<NodePortTuple> r){
		log.info("-- ROUTE --");
		for(int i = 0; i < r.size(); i++) log.info("> {}", r.get(i));
	}

	//***************
	// NESTED CLASSES
	//***************

	/** HiddenPacket thread to send HP to desired switches
	 *
	 **/
	public class HiddenPacketWorker extends Thread {
		protected IFloodlightProviderService provider;

		//K = unique hash , V = time_sent, src_sw, dst_sw
		private Map<Integer, String[]> packetMap;
		private String h1_IP;
		private String h2_IP;


		public HiddenPacketWorker(IFloodlightProviderService provider,
								  Map<Integer, String[]> packetMap) {
			this.provider = provider;
			this.packetMap = packetMap;
		}

		public void run() {

			while (true) { //Continually verify links forever
				log.info("\n\n\nHPV ROUND\n\n\n");

				get_host_devices();

				if(deviceMap.size() < 2) {
					log.info("HPV: Not enough devices detected...");
					try{
						Thread.sleep(1000);
					} catch (InterruptedException e){
						log.info("Thread interrupted");
					}
					continue;
				}

				//Randomly select end-to-end hosts
				String[] hosts = get_random_host_addr();
				this.h1_IP = hosts[0];
				this.h2_IP = hosts[1];



				//Calculate route between these hosts
				IOFSwitch srcSw, dstSw;
				try {
					srcSw =  provider.getSwitch((deviceMap.get(h1_IP).getAttachmentPoints()[0]).getSwitchDPID());
					dstSw = provider.getSwitch((deviceMap.get(h2_IP).getAttachmentPoints()[0]).getSwitchDPID());
				} catch (ArrayIndexOutOfBoundsException e) {
					log.info("HPV: No attachment point");
					continue;
				}
				
				List<NodePortTuple> route;				
				try {
					route = get_route((deviceMap.get(h1_IP).getAttachmentPoints()[0]), (deviceMap.get(h2_IP).getAttachmentPoints()[0])).getPath();
				} catch (NullPointerException e) {
					log.info("HPV: No route found between {} and {}", h1_IP, h2_IP);
					continue;
				}

				log.warn("HPV: {} -> {}, Route Size = {}",
						new Object[] {h1_IP,
								h2_IP,
								route.size(),
						});

				print_route(route);

				if (srcSw == null || dstSw == null) {
					log.info("HPV: Switch on path is offline");
					continue; //try again
				}

				if (route.size() < 4) {
					log.info("HPV: Only 1 switch on path, no links to check");
					continue; //try again
				}

				//Begin verifying links in path
				boolean complete = false; //has the verification process completed?
				int index = route.size() - 2; //route.size - 2, in order to get the packets entry port on the last switch
				boolean reverse = false; //reverse the verification direction

				while (!complete) {

					log.info("HPV: Destination set to index in route {}/{}", index, route.size() - 1);

					//down to one switch
					if ((!reverse && index < 2) || (reverse && index > route.size() - 3)) {
						log.warn("HPV: Suspicious Link = ({}, {}) -> ({}, {})", //suspicious first link
								new Object[] {route.get(index + (reverse ? -1 : 1)).getNodeId(),
										route.get(index + (reverse ? -1 : 1)).getPortId(),
										route.get(index + (reverse ? -2 : 2)).getNodeId(),
										route.get(index + (reverse ? -2 : 2)).getPortId(),
								});
						publishVerification(route, index, reverse);
						if (reverse) {
							complete = true;
						} else {
							log.warn("HPV: Reversing direction of verification process");
							reverse = true;
							index = 1;
							srcSw = provider.getSwitch(route.get(route.size() - 2).getNodeId());
							
							//swap IP addresses so the packet is correct
							String tmp = h1_IP;
							h1_IP = h2_IP;
							h2_IP = tmp;
							tmp = null;
						}
						continue;
					}

					dstSw = provider.getSwitch(route.get(index).getNodeId());
					if (dstSw == null) {
						log.info("HPV: Switch {} on path is offline", route.get(index).getNodeId());
						break;
					}

					Ethernet eth = generate_payload();
					OFPacketOut po;
					if (!reverse) po = generate_packet_out(eth, route.get(0).getPortId(), route.get(1).getPortId());
					else po = generate_packet_out(eth, route.get(route.size() - 1).getPortId(), route.get(route.size() - 2).getPortId());
				
					OFMessage flowMod = generate_flow_rule(eth, route.get(index).getPortId());
					int hash = eth.getPayload().hashCode();

					try {
						//Install rule in current end-point
						log.info("HPV: Sending Flow-Mod to {}", dstSw.getStringId());
						dstSw.write(flowMod, null);
						dstSw.flush();
						
						//give the rule a chance to install
						Thread.sleep(100);

						//Send Hidden Packet
						log.info("HPV: Sending packet ({}) to {}", hash, srcSw.getStringId());
						srcSw.write(po, null);
						srcSw.flush();

						//Put the hidden packet into the map
						String[] info = {dstSw.getStringId(), Long.toString(System.currentTimeMillis())};
						packetMap.put(hash, info);

						//Wait for HP return
						Thread.sleep(1000);
						
						if (packetMap.containsKey(hash)){
							log.warn("HPV: HiddenPacket was not returned, reducing path by 1 link");
							packetMap.remove(hash);
						} else {							
							log.warn("HPV: HiddenPacket successfully returned");

							//if this is not the end-point switch,
							//then the next hop in the path is suspicious
							//as this is where the packet was lost in the previous round
							if ((!reverse && index != route.size() - 2) || (reverse && index != 1)) {
								log.warn("HPV: Suspicious Link = ({}, {}) -> ({}, {})",
										new Object[] {route.get(index + (reverse ? -1 : 1)).getNodeId(),
												route.get(index + (reverse ? -1 : 1)).getPortId(),
												route.get(index + (reverse ? -2 : 2)).getNodeId(),
												route.get(index + (reverse ? -2 : 2)).getPortId(),
										});
							} else  {
								log.warn("HPV: All links on path have been verified");
								publishVerification(route, index, reverse);
							}
							
							if (reverse) {
								complete = true;
							} else {
								log.warn("HPV: Reversing direction of verification process");
								reverse = true;
								index = -1;
								srcSw = provider.getSwitch(route.get(route.size() - 2).getNodeId());
								
								//swap IP addresses so the packet is correct
								String tmp = h1_IP;
								h1_IP = h2_IP;
								h2_IP = tmp;
								tmp = null;
							}
						}

					} catch (IOException e) {
						log.error("Cannot write probing message to SW " + srcSw.getStringId());

					} catch (InterruptedException e) {
						//interrupted thread from receive method() to force wake up
						log.error("HPV Thread Interruption");
					}
					
					index += reverse ? 2 : -2; //a switch consumes two indexes
				}

			}

		}
		
		public void publishVerification(List<NodePortTuple> route, int index, boolean reverse) {
			
			//This method is damn ugly and could definitely be reworked
			
			long now = System.currentTimeMillis();
			
			if (!reverse) {
			
				for (int i = 0; i < route.size() - 2 && i <= index; i += 2) {
					
					Link link = new Link(route.get(i + 1).getNodeId(), route.get(i + 1).getPortId(), route.get(i + 2).getNodeId(), route.get(i + 2).getPortId());
					LinkInfo linkInfo = linkEngine.getLinks().get(link);
					if (linkInfo != null) {
						linkInfo.setLastHpvReceivedTime(now);
						if (i < index) {
							linkInfo.setHpvVerifiedStatus(true);
						} else {
							log.warn("Publish bad link at {} : {} -> {} : {}", new Object[] {link.getSrc(), link.getSrcPort(), link.getDst(), link.getDstPort()});
							linkInfo.setHpvVerifiedStatus(false);
						}
					}
					
					//do reverse link as well (assumption that all links are bidirectional)
					
					Link reverseLink = new Link(link.getDst(), link.getDstPort(), link.getSrc(), link.getSrcPort());
					linkInfo = linkEngine.getLinks().get(reverseLink);
					if (linkInfo != null) {
						linkInfo.setLastHpvReceivedTime(now);
						if (i < index) {
							linkInfo.setHpvVerifiedStatus(true);
						} else {
							log.warn("Publish bad link at {} : {} -> {} : {}", new Object[] {link.getSrc(), link.getSrcPort(), link.getDst(), link.getDstPort()});
							linkInfo.setHpvVerifiedStatus(false);
						}
					}
				}
			
			} else {
				for (int i = route.size() - 1; i > 1 && i >= index; i -= 2) {
					
					Link link = new Link(route.get(i - 1).getNodeId(), route.get(i - 1).getPortId(), route.get(i - 2).getNodeId(), route.get(i - 2).getPortId());
					LinkInfo linkInfo = linkEngine.getLinks().get(link);
					if (linkInfo != null) {
						linkInfo.setLastHpvReceivedTime(now);
						if (i > index) {
							linkInfo.setHpvVerifiedStatus(true);
						} else {
							log.warn("Publish bad link at {} : {} -> {} : {}", new Object[] {link.getSrc(), link.getSrcPort(), link.getDst(), link.getDstPort()});
							linkInfo.setHpvVerifiedStatus(false);
						}
					}
					
					//do reverse link as well (assumption that all links are bidirectional)
					
					Link reverseLink = new Link(link.getDst(), link.getDstPort(), link.getSrc(), link.getSrcPort());
					linkInfo = linkEngine.getLinks().get(reverseLink);
					if (linkInfo != null) {
						linkInfo.setLastHpvReceivedTime(now);
						if (i > index) {
							linkInfo.setHpvVerifiedStatus(true);
						} else {
							log.warn("Publish bad link at {} : {} -> {} : {}", new Object[] {reverseLink.getSrc(), reverseLink.getSrcPort(), reverseLink.getDst(), reverseLink.getDstPort()});
							linkInfo.setHpvVerifiedStatus(false);
						}
					}
				}
			}
			
		}

		public Ethernet generate_payload(){
			byte[] randomBytes = new byte[15];
			new Random().nextBytes(randomBytes);

			Ethernet eth = (Ethernet) new Ethernet()
					.setSourceMACAddress(deviceMap.get(h1_IP).getMACAddressString())
					.setDestinationMACAddress(deviceMap.get(h2_IP).getMACAddressString())
					.setEtherType(Ethernet.TYPE_IPv4)
					.setPayload(
							new IPv4()
									.setTtl((byte) 128)
									.setSourceAddress(h1_IP)
									.setDestinationAddress(h2_IP)
									.setProtocol((byte) 17)
									.setPayload(new UDP()
											.setSourcePort((short) 20)
											.setDestinationPort((short) 30)
											.setPayload(new Data(randomBytes))));
			return eth;
		}

		public OFPacketOut generate_packet_out(Ethernet eth, short inPort, short outPort){
			byte[] data = eth.serialize();
			OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                    .getMessage(OFType.PACKET_OUT);
			po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	        //po.setInPort(OFPort.OFPP_NONE);
	        po.setInPort(inPort);
	        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length);
	        po.setPacketData(data);
			List<OFAction> actions = new ArrayList<>();
			OFActionOutput out = new OFActionOutput(outPort, (short) 0);
			actions.add(out);
			po.setActions(actions);
			po.setActionsLength(out.getLength());
			po.setLengthU(po.getLengthU() + po.getActionsLength());
			return po;
		}

		public OFMessage generate_flow_rule(IPacket packet, short inPort){
			OFMatch match = new OFMatch().loadFromPacket(packet.serialize(), inPort);

			List<OFAction> actions = new ArrayList<>();
			OFActionOutput out = new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue());
			out.setMaxLength((short)0xffff);
			actions.add(out);
			
			OFMessage flowMod = ((OFFlowMod) provider.getOFMessageFactory().getMessage(OFType.FLOW_MOD))
					.setMatch(match)
					.setActions(actions)
					.setCommand(OFFlowMod.OFPFC_ADD)
					.setHardTimeout((short) 1) //timeout rule after 5 seconds
					.setIdleTimeout((short) 0)
					.setPriority(Short.MAX_VALUE)
					.setBufferId(OFPacketOut.BUFFER_ID_NONE)
					.setLengthU(OFFlowMod.MINIMUM_LENGTH+OFActionOutput.MINIMUM_LENGTH);

			return flowMod;
		}

	}

	//***************
	// IFloodlightModule
	//***************
	@Override
	public String getName() {
		return MODULE_NAME;
	}

	@Override
	public void init(FloodlightModuleContext cntx) throws FloodlightModuleException {
		floodlightProvider = cntx.getServiceImpl(IFloodlightProviderService.class);
		routingEngine = cntx.getServiceImpl(IRoutingService.class);
		restApi = cntx.getServiceImpl(IRestApiService.class);

		linkEngine = cntx.getServiceImpl(ILinkDiscoveryService.class);
		deviceEngine = cntx.getServiceImpl(IDeviceService.class);

		log = LoggerFactory.getLogger(LinkVerifier.class);
		statManager = new StatisticsManager(linkEngine, floodlightProvider);
		hpvWorker = new HiddenPacketWorker(floodlightProvider, packetMap);

		rand = new Random();
	}

	@Override
	public void startUp(FloodlightModuleContext arg0) throws FloodlightModuleException {
		// OpenFlow messages we want to receive
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new LinkVerifierWebRoutable());

		statManager.start();
		hpvWorker.start();
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IRoutingService.class);
		l.add(IRestApiService.class);
		l.add(ILinkDiscoveryService.class);

		return l;

	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && (name.equals("forwarding") || name.equals("topology") ||name.equals("linkdiscovery")));

	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

}


