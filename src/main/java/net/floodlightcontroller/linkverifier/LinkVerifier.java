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

	private Map<NodePortTuple, StatLink> switchMap =new HashMap<>();//Key = SwitchID, Value=Map<Port, Link>
	private Map<NodePortTuple,Integer> deviceMap = new HashMap<>();//Key = SwitchID,Port Tuple, Value=HostIP
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

			/* IF LLDP, VERIFY STATISTICS OF LINKS */
			if(eth.getPayload() instanceof BSN) {
				BSN bsn = (BSN) eth.getPayload();
				if(bsn == null || bsn.getPayload() == null) return Command.STOP;
				if(bsn.getPayload() instanceof LLDP == false) return Command.CONTINUE;
				(new InternalStatisticsGetter((LLDP) bsn.getPayload(), sw, (OFPacketIn) msg, cntx, floodlightProvider)).start();
			} else if(eth.getPayload() instanceof LLDP) {
				(new InternalStatisticsGetter((LLDP) eth.getPayload(), sw, (OFPacketIn) msg, cntx, floodlightProvider)).start();
			} else if(eth.getPayload() instanceof IPv4) {
				IPv4 packet = (IPv4) eth.getPayload();

				if(packetMap.containsKey(packet.hashCode())) {
					List<String> info = packetMap.remove(packet.hashCode());
					log.info("A hidden packet has been returned to the controller");
					//(new HiddenPacket(floodlightProvider, deviceMap, packetMap).start();
				} else {
					return Command.CONTINUE; //not a HP, so process normally
				}
			}
			return Command.STOP;
		}
		return Command.CONTINUE;
	}

	//***************
	// NESTED CLASSES
	//***************

	public class WebGetter extends Thread {
		private final String ipAddress = "localhost";
		private final String port = "8080";
		private GetterType type;

		public WebGetter(GetterType type) {
			this.type = type;
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
            // TODO
			}
		}
		//TODO
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
		@SerializedName("entityClass")
		public String entityClass;

		@SerializedName("mac")
		public String[] mac;

		@SerializedName("ipv4")
		public String[] ipv4;

		@SerializedName("vlan")
		public String[] vlan;

		@SerializedName("attachmentPoint")
		public String[] attachmentPoint;

		@SerializedName("lastSeen")
		public int lastSeen;

		@SerializedName("dhcpClientName")
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
