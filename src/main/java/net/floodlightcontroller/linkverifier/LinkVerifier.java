package net.floodlightcontroller.linkverifier;

import java.io.IOException;
import java.util.*;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
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


	private Map<NodePortTuple, Link> linkMap =new HashMap<>();//Key = NodePortTuple, Value=Link
	private Map<String, IDevice> deviceMap = new HashMap<>();//Key =HostIP , Value= AttachmentPoints
	private Map<Integer, String[]> packetMap = new HashMap<>();//Key = PacketId, Value = {time, srcSw, dstSw}

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
						log.info("\n\nA hidden packet ({}) has been returned from {}\n\n", packet.hashCode(), sw.getStringId());
						packetMap.remove(packet.hashCode());
						return Command.STOP; //gobble up hidden packet
					}

					log.info("\n\nHidden packet ({}) returned from incorrect switch {}\n\n", packet.hashCode(), sw.getStringId());

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
						this.sleep(1000);
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
				IOFSwitch srcSw =  provider.getSwitch((deviceMap.get(h1_IP).getAttachmentPoints()[0]).getSwitchDPID());
				IOFSwitch dstSw = provider.getSwitch((deviceMap.get(h2_IP).getAttachmentPoints()[0]).getSwitchDPID());
				List<NodePortTuple> route = get_route((deviceMap.get(h1_IP).getAttachmentPoints()[0]),
						(deviceMap.get(h2_IP).getAttachmentPoints()[0])).getPath();

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

				while (!complete) {

					log.info("HPV: Checking Index in Route {}/{}", index, route.size() - 1);

					//down to one switch
					if (index < 2) {
						log.info("HPV: All links in path checked, suspicious first link", index);
						break; // finished verifying
					}

					dstSw = provider.getSwitch(route.get(index).getNodeId());
					if (dstSw == null) {
						log.info("HPV: Switch {} on path is offline", route.get(index).getNodeId());
						break;
					}

					IPacket eth = generate_payload();
					OFPacketOut po = generate_packet_out(eth, route.get(1).getPortId());
					//not sure if this should be eth or eth.getPayload
					//using eth gives a "data field empty" error
					OFMessage flowMod = generate_flow_rule(eth.getPayload(), route.get(index).getPortId());
					int hash = eth.getPayload().hashCode();

					try {
						//Install rule in current end-point
						log.info("HPV: Sending Flow-Mod to {}", dstSw.getStringId());
						dstSw.write(flowMod, null);
						dstSw.flush();

						//Send Hidden Packet
						log.info("HPV: Sending packet ({}) to {}", hash, srcSw.getStringId());
						srcSw.write(po, null);
						srcSw.flush();

						//Put the hidden packet into the map
						String[] info = {dstSw.getStringId(), Long.toString(System.currentTimeMillis())};
						packetMap.put(hash, info);

						//Wait for HP return
						this.sleep(500);
						
						if(packetMap.containsKey(hash)){
							log.warn("HPV: HiddenPacket was not returned, reducing path by 1 switch");
							packetMap.remove(hash);
						}
						else {							
							
							//issue of a HPV being received by the correct switch, but after the delay
							//migrate logic into the receive()?
							log.warn("HPV: HiddenPacket successfully returned");

							//if this is not the end-point switch,
							//then the next hop in the path is suspicious
							//as this is where the packet was lost in the previous round
							if (index != route.size() - 2) {
								log.warn("\n\n\nHPV: Suspicious Link = ({}, {}) -> ({}, {})\n\n\n",
										new Object[] {route.get(index).getNodeId(),
												route.get(index).getPortId(),
												route.get(index + 1).getNodeId(),
												route.get(index + 1).getPortId(),
										});
							}
							else log.warn("All links on path have been verified");
							complete = true;
						}

					} catch (IOException e) {
						log.error("Cannot write probing message to SW " + srcSw.getStringId());

					} catch (InterruptedException e) {
						//interrupted thread from receive method() to force wake up
						log.error("HPV Thread Interruption");
					}
					index -= 2; //-2 to get entry port
				}

			}

		}

		public IPacket generate_payload(){
			byte[] randomBytes = new byte[15];
			new Random().nextBytes(randomBytes);

			IPacket eth = new Ethernet()
					.setSourceMACAddress(deviceMap.get(h1_IP).getMACAddressString())
					.setDestinationMACAddress(deviceMap.get(h2_IP).getMACAddressString())
					.setEtherType(Ethernet.TYPE_IPv4)
					.setPayload(
							new IPv4()
									.setTtl((byte) 128)
									.setSourceAddress(h1_IP)
									.setDestinationAddress(h2_IP)
									.setPayload(new UDP()
											.setSourcePort((short) deviceMap.get(h1_IP).getAttachmentPoints()[0].getPort())
											.setDestinationPort((short) deviceMap.get(h2_IP).getAttachmentPoints()[0].getPort())
											.setPayload(new Data(randomBytes))));
			return eth;
		}

		public OFPacketOut generate_packet_out(IPacket eth, short outPort){

			List<OFAction> actions = new ArrayList<>();
			OFActionOutput out = (OFActionOutput) provider.getOFMessageFactory().getAction(OFActionType.OUTPUT);
			out.setPort(outPort);
			actions.add(out);

			OFPacketOut po = (OFPacketOut) provider.getOFMessageFactory().getMessage((OFType.PACKET_OUT));
			byte[] data = eth.serialize();

			po.setPacketData(data);
			po.setActions(actions);
			po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
			po.setInPort(OFPort.OFPP_NONE);
			po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
			po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length + po.getActionsLength());

			return po;
		}

		public OFMessage generate_flow_rule(IPacket packet, short port){
			OFMatch match = new OFMatch().loadFromPacket(packet.serialize(), port);

			List<OFAction> actions = new ArrayList<>();
			OFActionOutput out = (OFActionOutput) provider.getOFMessageFactory().getAction(OFActionType.OUTPUT);
			out.setPort(OFPort.OFPP_CONTROLLER.getValue());
			actions.add(out);

			OFMessage flowMod = ((OFFlowMod) provider.getOFMessageFactory().getMessage(OFType.FLOW_MOD))
					.setMatch(match)
					.setActions(actions)
					.setBufferId(OFPacketOut.BUFFER_ID_NONE)
					.setCommand(OFFlowMod.OFPFC_ADD)
					.setHardTimeout((short)1) //timeout rule after 5 seconds
					.setBufferId(OFPacketOut.BUFFER_ID_NONE)
					.setOutPort(OFPort.OFPP_CONTROLLER)
					.setPriority(Short.MAX_VALUE)
					.setLength((short) (OFFlowMod.MINIMUM_LENGTH + out.getLength()));

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


