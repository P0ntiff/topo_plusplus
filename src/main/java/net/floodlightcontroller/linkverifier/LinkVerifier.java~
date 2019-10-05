package net.floodlightcontroller.linkverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.web.SwitchStatisticsResource;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.linkdiscovery.web.LinksResource;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.topology.TopologyInstance;
import net.floodlightcontroller.topology.TopologyManager;
import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;
import org.sdnplatform.sync.internal.config.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;



/*
 * TOPOGUARD++ CLASS FOR VERIFICATION OF FLOW BETWEEN LINKS
 */
public class LinkVerifier implements IOFMessageListener, IFloodlightModule<IFloodlightService> {

// Instance Variables
	protected IFloodlightProviderService floodlightProvider;
	protected IRoutingService routingEngine;
	protected ILinkDiscoveryService linkEngine;
	protected IDeviceService deviceEngine;
	protected IDeviceService statisticsEngine;
    protected static Logger log;
    public static final String MODULE_NAME = "linkverifier";
    protected TopologyInstance currentInstance;

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

			if(eth.getPayload() instanceof IPv4) { /* IF IPV4, CHECK IF HIDDEN PACKET */
				get_host_devices();

//				if(packetMap.isEmpty() && !deviceMap.isEmpty()) {
//
//					new HiddenPacketWorker(floodlightProvider, packetMap, ).start();
//				}

				IPv4 packet = (IPv4) eth.getPayload();
				log.info("Received {}", packet.hashCode());
				//if the pkt hash is in the system, and this is the expected switch for it
				if(packetMap.containsKey(packet.hashCode())) {
					String[] info = packetMap.remove(packet.hashCode());
					log.info("\n\nA hidden packet has been returned to the controller\n\n");
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
		for(IDevice d : deviceEngine.getAllDevices()){
			Integer[] addrs = d.getIPv4Addresses();
			if(addrs.length == 0) continue;
			deviceMap.put(IPv4.fromIPv4Address(addrs[0]), d);
		}
		log.info("{} devices added...", deviceMap.size());
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
				
				//grab two new random hosts
				String[] hosts = get_random_host_addr();
				this.h1_IP = hosts[0];
				this.h2_IP = hosts[1];
			
				log.warn("HPV: {} -> {}", h1_IP, h2_IP);
		        IOFSwitch srcSw =  provider.getSwitch((deviceMap.get(h1_IP).getAttachmentPoints()[0]).getSwitchDPID());
		        IOFSwitch dstSw = provider.getSwitch((deviceMap.get(h2_IP).getAttachmentPoints()[0]).getSwitchDPID());
		        List<NodePortTuple> route = get_route((deviceMap.get(h1_IP).getAttachmentPoints()[0]),
														(deviceMap.get(h2_IP).getAttachmentPoints()[0])).getPath();
		
		        if (route.size() < 4) { // I think 4 is the right number here? Correct me if I am wrong - Luke
		        	log.warn("Only 1 switch on path, no links to check");
		            break; //do nothing, no links to check
		        }
		        
		        if (srcSw == null || dstSw == null) {
		            log.warn("Switch on path is offline");
		            break; //switch is offline, do nothing
		        }
		        
		        //begin verifying links on path
		        boolean complete = false; //has the verification proccess completed?
		        int index = route.size() - 2;
		        
		        while (!complete) {
		        	
		        	if (index < 4) break; // finished verifying
		        	
		        	dstSw = provider.getSwitch(route.get(index).getNodeId());
		        	if (dstSw == null) {
		        		log.warn("Switch on path is offline");
			            return; //switch is offline, do nothing
		        	}
	
			        IPacket eth = generate_payload();
			        OFPacketOut po = generate_packet_out(generate_payload());
					//route.size - 2, in order to get the packets entry port on the last switch
			        OFMessage flowMod = generate_flow_rule(eth.getPayload(), route.get(index).getPortId());
			
			        int hash = eth.getPayload().hashCode();
			        try {
			        	log.info("Sending FlowMod into the system");
			            //INSTALL FLOW RULE IN END POINT
			            dstSw.write(flowMod, null);
			            dstSw.flush();
			
						log.info("Sending HPV {} into the system", hash);
			            //SEND HIDDEN PACKET INTO SYSTEM
			            srcSw.write(po, null);
			            srcSw.flush();
			
			            String[] info = {dstSw.getStringId(), Long.toString(System.currentTimeMillis())};
			            packetMap.put(hash, info);
			
			            //WAIT FOR IT TO RETURN
			            Thread.sleep(500); //TODO use the receive method to wake up the thread early to speed things up
			
			            if(packetMap.containsKey(hash)){
			                log.warn("HP WAS NOT RETURNED IN 500ms");
			                log.warn("Reducing path by 1 switch");
			            } else {
			                log.warn("HP WAS RETURNED IN 500ms");
			                if (index != route.size() - 2) log.warn("Found bad link between switch x and switch y"); //TODO append link details
			                else log.warn("All links on path have been verified");
			                complete = true;
			            }
			
			        } catch (Exception e) {
			            log.error("Cannot write probing message to SW " + srcSw.getStringId());
			            // gotta catch 'em all
			            // TODO fix this exception handling to be more specific
			        }
			        
			        index -= 2; // I think it is -2 because each switch as an in and an out. (untested)
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

		public OFPacketOut generate_packet_out(IPacket eth){

			OFPacketOut po = (OFPacketOut) provider.getOFMessageFactory().getMessage((OFType.PACKET_OUT));
			byte[] data = eth.serialize();

			List<OFAction> actions = new ArrayList<OFAction>();
			actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue(),
					(short)0xFFFF));

			po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
			po.setInPort(OFPort.OFPP_NONE);
			po.setPacketData(data);
			po.setActions(actions);
			po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

			// set data and data length
			po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length + po.getActionsLength() );

			return po;
		}

		public OFMessage generate_flow_rule(IPacket packet, short dstPort){
			OFMatch match = new OFMatch().loadFromPacket(packet.serialize(), OFPort.OFPP_ALL.getValue());

			List<OFAction> actions = new ArrayList<>();
			actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

			OFMessage flowMod = ((OFFlowMod) provider.getOFMessageFactory().getMessage(OFType.FLOW_MOD))
					.setActions(actions)
					.setBufferId(OFPacketOut.BUFFER_ID_NONE)
					.setCommand(OFFlowMod.OFPFC_ADD)
					.setHardTimeout((short)5) //timeout rule after 5 seconds
					.setMatch(match)
					.setBufferId(OFPacketOut.BUFFER_ID_NONE)
					.setOutPort(OFPort.OFPP_NONE)
					.setPriority(Short.MAX_VALUE)
					.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

			return flowMod;
		}

	}
	/*
	public class WebGetter extends Thread {
		private final String ipAddress = "localhost";
		private final String port = "8080";
		private GetterType type;
		private Map<String, List<NodePortTuple>> deviceMap; //Key = IP, Value = List of PoA's
		private Map<Link, LinkInfo> linkMap; //Key = NodePortTuple, Value=Link
		private NodePortTuple startPoint;
		private NodePortTuple endPoint;

		public WebGetter(GetterType type, Map<String, List<NodePortTuple>> deviceMap,
						 Map<Link, LinkInfo> linkMap, NodePortTuple startPoint, NodePortTuple endPoint) {
			this.type = type;
			this.deviceMap = deviceMap;
			this.linkMap = linkMap;
			this.startPoint = startPoint;
			this.endPoint = endPoint;
		}

		public WebGetter() {
			//constructor used for utility methods
		}

		public BufferedReader makeWebRequest(String path) throws IOException {
			URL url = new URL("http://" + ipAddress + ":" + port + path);
			URLConnection con = url.openConnection();
			InputStream is = con.getInputStream();
			return new BufferedReader(new InputStreamReader(is));
		}

		public void run() {
			switch (type) {
				case DEVICES:

					break;
				case ROUTES:
					log.info("Getting route information...");
					Route route =
							routingEngine.getRoute(startPoint.getNodeId(),
									startPoint.getPortId(),
									endPoint.getNodeId(),
									endPoint.getPortId(), 0); //cookie = 0, i.e., default route
					//TODO do something with this
					break;
				case LINKS:
					log.info("Getting link information...");
					linkMap = linkEngine.getLinks();

					break;
				default:
					break;
			}
			return;
		}

		public void get_devices() {
			try {
				Gson gson = new Gson();
				BufferedReader linkReq = makeWebRequest("/wm/device/");
				List<DeviceInfo> devices = gson.fromJson(linkReq, new TypeToken<LinkedList<DeviceInfo>>() {
				}.getType());
				parse_devices(devices);
			} catch (Exception e) {
				log.warn("\n\nError in get_devices WebRequest {}\n\n", e);
			}
		}

		public void parse_devices(List<DeviceInfo> devices) {
			log.info("Parsing deivces...");
			for (DeviceInfo d : devices) {
				if (d.ipv4.length == 0) continue;

				List<NodePortTuple> values = new ArrayList<>();

				for (Map<String, String> info : d.attachmentPoint) {
					long dpid = Long.parseLong(info.get("switchDPID").replace(":", ""));
					NodePortTuple val = new NodePortTuple(dpid, Short.parseShort(info.get("port")));

					values.add(val);
				}

				deviceMap.put(d.ipv4[0], values);

			}

			log.info("Device map of size {}", deviceMap.size());

		}

		public void get_links() {
			try {
				Gson gson = new Gson();
				BufferedReader linkReq = makeWebRequest("/wm/topology/links/json");
				List<StatLink> links = gson.fromJson(linkReq, new TypeToken<LinkedList<StatLink>>() {
				}.getType());
				parse_links(links);
			} catch (Exception e) {
				log.warn("\n\nError in Link Verification WebRequest {}\n\n", e);
			}

		}

		public void parse_links(List<StatLink> links) {
			for (StatLink l : links) {
				NodePortTuple PoA = new NodePortTuple(Long.parseLong(l.src_switch), l.src_port);
				log.warn("Parsing Link from ({} , {}) on ports ({}, {})",
						new Object[]{l.src_switch,
								l.dst_switch,
								l.src_port,
								l.dst_port,
						});
			}
		}



		//***************
		// GSON CLASSES
		//***************


		public class DeviceInfo {

			public String entityClass;
			public String[] mac;
			public String[] ipv4;
			public String[] vlan;
			public Map<String, String>[] attachmentPoint;
			public long lastSeen;
			public String dhcpClientName;


			public DeviceInfo() {
				// add stuff later
			}

			public String toString() {
				StringBuilder sb = new StringBuilder();
				sb.append("--------- device description ---------\n");
				sb.append("entityClass: ");
				sb.append(entityClass);

				sb.append("\n--------- device description  end ---------\n");
				return sb.toString();

			}
		}

		public class StatLink {
			@SerializedName("src-switch")
			public String src_switch;

			@SerializedName("src-port")
			public int src_port;

			@SerializedName("dst-switch")
			public String dst_switch;

			@SerializedName("dst-port")
			public int dst_port;

			public String type;
			public String direction;
			public int latency;

			public StatLink() {
				// add stuff later
			}

			public String toString() {
				StringBuilder sb = new StringBuilder();
				sb.append("--------- link description ---------\n");
				sb.append("src-switch: ");
				sb.append(src_switch);
				sb.append("\nsrc-port: ");
				sb.append(src_port);
				sb.append("\ndst-switch: ");
				sb.append(dst_switch);
				sb.append("\ndst-port: ");
				sb.append(dst_port);
				sb.append("\ntype: ");
				sb.append(type);
				sb.append("\ndirection: ");
				sb.append(direction);
				sb.append("\nlatency: ");
				sb.append(latency);
				sb.append("\n----- link description  end -----");

				return sb.toString();

			}
		}

		public class PortStat {

			public String portNumber; // 1,2,3 etc or "local"
			public long receivePackets;
			public long transmitPackets;
			public long receiveBytes;
			public long transmitBytes;
			public long receiveDropped;
			public long transmitDropped;
			public long receiveErrors;
			public long transmitErrors;
			public long receiveFrameErrors;
			public long receiveOverrunErrors;
			public long receiveCRCErrors;
			public long collisions;

			public PortStat() {
				// might need me later
			}

			public String toString() {
				StringBuilder sb = new StringBuilder();

				sb.append("---------- port statistics --------");
				sb.append("\nport_number: ");
				sb.append(portNumber);
				sb.append("\nreceive_packets: ");
				sb.append(receivePackets);
				sb.append("\ntransmit_packets: ");
				sb.append(transmitPackets);
				sb.append("\nreceive_bytes: ");
				sb.append(receiveBytes);
				sb.append("\ntransmit_bytes: ");
				sb.append(transmitBytes);
				sb.append("\nreceive_dropped: ");
				sb.append(receiveDropped);
				sb.append("\ntransmit_dropped: ");
				sb.append(transmitDropped);
				sb.append("\nreceive_errors: ");
				sb.append(receiveErrors);
				sb.append("\ntransmit_errors: ");
				sb.append(transmitErrors);
				sb.append("\nreceive_frame_errors: ");
				sb.append(receiveFrameErrors);
				sb.append("\nreceive_overrun_errors: ");
				sb.append(receiveOverrunErrors);
				sb.append("\nreceive_CRC_errors: ");
				sb.append(receiveCRCErrors);
				sb.append("\ncollisions: ");
				sb.append(collisions);
				sb.append("\n---------- end --------");

				return sb.toString();
			}
		}
	}

*/


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
		statManager.start();
		hpvWorker.start();
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
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
		return (type.equals(OFType.PACKET_IN) && name.equals("linkdiscovery"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

}
