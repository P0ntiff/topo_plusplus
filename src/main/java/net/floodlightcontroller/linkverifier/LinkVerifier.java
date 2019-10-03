package net.floodlightcontroller.linkverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import jdk.nashorn.internal.objects.annotations.Getter;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.topology.NodePortTuple;
import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;


/*
 * TOPOGUARD++ CLASS FOR VERIFICATION OF FLOW BETWEEN LINKS
 */
public class LinkVerifier implements IOFMessageListener, IFloodlightModule<IFloodlightService> {

// Instance Variables
	protected IFloodlightProviderService floodlightProvider;
    protected static Logger log;
    public static final String MODULE_NAME = "linkverifier";

	private Map<NodePortTuple, StatLink> switchMap =new HashMap<>();//Key = NodePortTuple, Value=Link
	private Map<String, List<NodePortTuple>> deviceMap = new HashMap<>();//Key =HostIP , Value= AttachmentPoints
	private Map<Integer, List<String>> packetMap = new HashMap<>();//Key = PacketId, Value = {time, srcSw, dstSw}

	enum GetterType {
		DEVICES,
		ROUTES,
	}

//- - -

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		if(msg.getType().equals(OFType.PACKET_IN)) {
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);


			if(eth.getPayload() instanceof BSN) { /* IF LLDP, VERIFY STATISTICS OF LINKS */
				BSN bsn = (BSN) eth.getPayload();
				if(bsn == null || bsn.getPayload() == null) return Command.STOP;
				if(bsn.getPayload() instanceof LLDP == false) return Command.CONTINUE;
				(new InternalStatisticsGetter((LLDP) bsn.getPayload(), sw, (OFPacketIn) msg, cntx, floodlightProvider)).start();
				return Command.STOP;
			} else if(eth.getPayload() instanceof LLDP) {
				(new InternalStatisticsGetter((LLDP) eth.getPayload(), sw, (OFPacketIn) msg, cntx, floodlightProvider)).start();
				return Command.STOP;
			} else if(eth.getPayload() instanceof IPv4) { /* IF IPV4, CHECK IF HIDDEN PACKET */
				IPv4 packet = (IPv4) eth.getPayload();

				if(packetMap.containsKey(packet.hashCode())) {
					List<String> info = packetMap.remove(packet.hashCode());
					log.info("A hidden packet has been returned to the controller");
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
	 * Randomly selects a host IP addresses from the DeviceMap
	 * @return int host IP address
	 */
	public int get_random_host_addr(){
		Random generator = new Random();
		Object[] ips = deviceMap.keySet().toArray();
		int IP1 = (int)ips[generator.nextInt(ips.length)];
		return IP1;
	}



	//***************
	// NESTED CLASSES
	//***************

	/** HiddenPacket thread to send HP to desired switches
	 *
	 **/
	public class HiddenPacket extends Thread {
		protected IFloodlightProviderService provider;

		//host map, K = Switch/Port Pair, V = Host_IP
		private Map<Integer, NodePortTuple> deviceMap;
		private Map<Integer, List<String>> packetMap;
		private int h1;
		private int h2;


		public HiddenPacket(IFloodlightProviderService provider,
							Map<Integer, NodePortTuple> deviceMap,
							Map<Integer, List<String>> packetMap,
							int[] hostIPs) {
			this.provider = provider;
			this.deviceMap = deviceMap;
			this.packetMap = packetMap;
			this.h1 = hostIPs[0];
			this.h1 = hostIPs[1];
		}

		public void run() {
/*
        IOFSwitch srcSw = provider.getSwitch((deviceMap.get(h1)).getNodeId());
        IOFSwitch dstSw = provider.getSwitch((deviceMap.get(h2)).getNodeId());


        if (srcSw == null || dstSw == null) {
            log.warn("Switch on path is offline");
            return; //switch is offline, do nothing
        }

        Ethernet eth = generate_payload();
        OFPacketOut po = generate_packet_out(eth);
        OFMessage flowMod = generate_flow_rule((IPv4)eth.getPayload());

        try {
            //INSTALL FLOW RULE IN END POINT
            dstSw.write(flowMod, null);
            dstSw.flush();

            //SEND HIDDEN PACKET INTO SYSTEM

            srcSw.write(po, null);
            srcSw.flush();
            log.info("HP SENT INTO SYSTEM {}", (eth.getPayload()).hashCode());
            Thread.sleep(500);

            if(packetMap.containsKey(eth.getPayload().hashCode())){
                log.warn("HP WAS NOT RETURNED IN 500ms");
            } else {
                log.warn("HP WAS RETURNED IN 500ms");
            }

        } catch (Exception e) {
            log.error("Cannot write probing message to SW " + srcSw.getStringId());
        }
*/

			return;
		}

/*
    public Ethernet generate_payload(){
        //just PING for the moment, but should randomly select payload type

        IPacket packet = new IPv4()
                .setProtocol(IPv4.PROTOCOL_ICMP)
                .setSourceAddress(deviceMap.get(startPoint))
                .setDestinationAddress(deviceMap.get(endPoint))
                .setPayload(new ICMP()
                        .setIcmpType((byte) 8)
                        .setIcmpCode((byte) 0)
                        .setPayload(new Data(new byte[]
                                {0x76, (byte) 0xf2, 0x0, 0x2, 0x1, 0x1, 0x1}))
                );

        //not sure how next hop works for controller
        Ethernet eth = new Ethernet().setSourceMACAddress("aa:aa:aa:aa:aa:aa")
                .setDestinationMACAddress("bb:bb:bb:bb:bb:bb")
                .setEtherType(Ethernet.TYPE_IPv4);

        eth.setPayload(packet);
        return eth;
    }*/

		public OFPacketOut generate_packet_out(Ethernet eth){

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

		public OFMessage generate_flow_rule(IPv4 packet){
			//TODO this port should be changed when shortest route is figured out
			OFMatch match = new OFMatch().loadFromPacket(packet.serialize(), OFPort.OFPP_ALL.getValue());

			List<OFAction> actions = new ArrayList<>();
			actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

			OFMessage flowMod = ((OFFlowMod) provider.getOFMessageFactory().getMessage(OFType.FLOW_MOD))
					.setMatch(match).setCommand(OFFlowMod.OFPFC_ADD)
					.setOutPort(OFPort.OFPP_NONE)
					.setActions(actions)
					.setHardTimeout((short)5) //timeout rule after 5 seconds
					.setPriority((short)1).setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));
			return flowMod;
		}

	}


	public class WebGetter extends Thread {
		private final String ipAddress = "localhost";
		private final String port = "8080";
		private GetterType type;
		private Map<String, List<NodePortTuple>> deviceMap; //Key = IP, Value = List of PoA's

		public WebGetter(GetterType type, Map<String, List<NodePortTuple>> deviceMap) {
			this.type = type;
			this.deviceMap = deviceMap;
		}

		public BufferedReader makeWebRequest(String path) throws IOException {
			URL url = new URL("http://" + ipAddress + ":" + port + path);
			URLConnection con = url.openConnection();
			InputStream is = con.getInputStream();
			return new BufferedReader(new InputStreamReader(is));
		}

		public void run(){
			switch(type){
				case DEVICES:
					log.info("Updating LinkVerifier map information...");
					get_devices();
					break;
				case ROUTES:
					log.info("Getting route information...");
					break;
				default:
					break;
			}
			return;
		}

		public void get_devices(){
			try {
				Gson gson = new Gson();
				BufferedReader linkReq = makeWebRequest("/wm/device/");
				List<DeviceInfo> devices = gson.fromJson(linkReq, new TypeToken<LinkedList<DeviceInfo>>() {}.getType());
				parse_devices(devices);
			} catch (Exception e) {
				log.warn("\n\nError in get_devices WebRequest {}\n\n", e);
			}
		}

		public void parse_devices(List<DeviceInfo> devices) {
			for(DeviceInfo d : devices) {
				List<NodePortTuple> values =  new ArrayList<>();

				for(Map<String, String> info : d.attachmentPoint) {
					NodePortTuple val = new NodePortTuple(Long.parseLong(info.get("switchDPID")),
							Short.parseShort(info.get("port")));
					values.add(val);
				}

				deviceMap.put(d.ipv4[0], values);

			}

		}

		public void get_route(String src_dpid, int src_port, String dst_dpid, int dst_port){
			try {
				Gson gson = new Gson();
				BufferedReader linkReq = makeWebRequest("/route" +
						"/" + src_dpid +
						"/" + src_port +
						"/" + dst_dpid +
						"/" + dst_port + "/json");

				//Route routes = gson.fromJson(linkReq, new TypeToken<LinkedList<Route>>() {}.getType());
				//parse_route(routes);
			} catch (Exception e) {
				log.warn("\n\nError in Link Verification WebRequest {}\n\n", e);
			}
		}
	}


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
		log = LoggerFactory.getLogger(LinkVerifier.class);
	}

	@Override
	public void startUp(FloodlightModuleContext arg0) throws FloodlightModuleException {
		// OpenFlow messages we want to receive
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		
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
