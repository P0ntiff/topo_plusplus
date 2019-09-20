package net.floodlightcontroller.linkverifier;

import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedList;
import java.util.List;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;


/*
 * TOPOGUARD++ CLASS FOR VERIFICATION OF FLOW BETWEEN LINKS
 */
public class LinkVerifier implements IOFMessageListener, IFloodlightModule<IFloodlightService> {

// Instance Variables
	protected IFloodlightProviderService floodlightProvider;
    protected static Logger log;
    public static final String MODULE_NAME = "linkverifier";
	static String ipAddress = "localhost";
	static String port = "8080";
	//maps a Switch, to a collection of its ports and associated links
	protected Map<String, Map<Integer, StatLink>> switchMap = new HashMap<String, Map<Integer, StatLink>>();
    
//- - -

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		if(msg.getType().equals(OFType.PACKET_IN)) {
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			if(eth.getPayload() instanceof BSN) {
				BSN bsn = (BSN) eth.getPayload();
				if(bsn == null || bsn.getPayload() == null) return Command.STOP;
				if(bsn.getPayload() instanceof LLDP == false) return Command.CONTINUE;
				return verify_lldp_link((LLDP) bsn.getPayload(), sw, (OFPacketIn) msg, cntx);
			} else if(eth.getPayload() instanceof LLDP) {
				return verify_lldp_link((LLDP) eth.getPayload(), sw, (OFPacketIn) msg, cntx);
			}
		} 
		return Command.CONTINUE;
	}

	public Command verify_lldp_link(LLDP lldp, IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		int inPort = (int) msg.getInPort();
		log.warn("\nSwitchMap Size {}, Msg from {} on Port {}, InMap {}",
			new Object[] {switchMap.size(),
					sw.getStringId(),
					inPort,
					switchMap.containsKey(sw.getStringId())
			});

		if(!switchMap.containsKey(sw.getStringId())) {
			get_links();
		}

		StatLink l = switchMap.get(sw.getStringId()).get(inPort);
		if(l == null) {
			log.error("\nNull StatLink");
			return Command.STOP;
		} 
		log.warn("\n\n\n Verifying switch {}\n\n\n", l.src_switch);
		try {
			log.warn("\n{}", l.toString());
		/* HERE BE DRAGONS
			log.warn("\n\nRequesting Stats @ {}\n", System.currentTimeMillis());
			Gson gson = new Gson();
			BufferedReader srcStatRequest = makeWebRequest("/wm/core/switch/" + l.src_switch + "/port/json");
			log.warn("\n\nTime 1 @ {}\n", System.currentTimeMillis());
			BufferedReader dstStatRequest = makeWebRequest("/wm/core/switch/" + l.dst_switch + "/port/json");
			log.warn("\n\nTime 2 @ {}\n", System.currentTimeMillis());	

			log.warn("\n\nParsing Stats\n");
			@SuppressWarnings("unchecked")
			PortStat[] srcPortsStats = ((Map<String,PortStat[]>) gson.fromJson(srcStatRequest, new TypeToken<Map<String,PortStat[]>>() {}.getType())).get(l.src_switch);
			@SuppressWarnings("unchecked")
			PortStat[] dstPortsStats = ((Map<String,PortStat[]>) gson.fromJson(dstStatRequest, new TypeToken<Map<String,PortStat[]>>() {}.getType())).get(l.dst_switch);

			log.warn("\n\nFormalizing Stats\n");
			PortStat srcPort = null, dstPort = null;

			for (PortStat p : srcPortsStats) {
	    			if (p.portNumber.equals(String.valueOf(l.src_port))) {
	    				srcPort = p;
	    				break;
	    			}
	    		}
			
			for (PortStat p : dstPortsStats) {
	    			if (p.portNumber.equals(String.valueOf(l.dst_port))) {
	    				dstPort = p;
	    				break;
	    			}
	    		}
			log.warn("\n\nFinished Stats\n");
			log.warn("\n{}", l.toString());

			*/
			//TODO the is only flow direction, we should also consider the other direction (ie, dst -> src)
			
			/*
			//TODO set threshhold, 1000 is giga arbitrary
			if(Math.abs(srcPort.transmitBytes - dstPort.receiveBytes) > 1000) {
				log.warn("SUSPICIOUS LINK STATISTICS, DIFFERENCE OF {}", Math.abs(srcPort.transmitBytes - dstPort.receiveBytes));
			} */

		} catch (Exception e) {
			log.warn("ERROR: verify_lldp_link {}", e);
		}
		return Command.STOP;
	}

	public static BufferedReader makeWebRequest(String path) throws IOException {
		URL url = new URL("http://" + ipAddress + ":" + port + path);
		URLConnection con = url.openConnection();
        	InputStream is = con.getInputStream();
        	return new BufferedReader(new InputStreamReader(is));
	}

	public void get_links(){
		try {
			Gson gson = new Gson();
			BufferedReader linkReq = makeWebRequest("/wm/topology/links/json");
			List<StatLink> links = gson.fromJson(linkReq, new TypeToken<LinkedList<StatLink>>() {}.getType());
			parse_links(links);
		} catch (Exception e) {
			log.warn("\n\nError in Link Verification WebRequest {}\n\n", e);
		}
	}

	public void parse_links(List<StatLink> links) throws IOException {
		for(StatLink l : links) {
			Map<Integer, StatLink> portMap = new HashMap<Integer, StatLink>();
			portMap.put(l.src_port, l);
			switchMap.put(l.src_switch, portMap);
			log.warn("Parsing Link from ({} , {}) on ports ({}, {})",
				new Object[] {l.src_switch,
						l.dst_switch,
						l.src_port,
						l.dst_port,
				});
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
	
	
    //***************
    // NESTED CLASSES
    //***************
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

//	public class PortReplySpecifics {
//		
//		public String version;
//		public PortStat[] port;
//		
//		public PortReplySpecifics() {
//			//nothing for the moment;
//		}
//		
//		public PortStat getPortStat(String portNum) {
//			for (PortStat p : port) {
//				if (p.port_number.equals(portNum)) return p;
//			}
//			return null;
//		}
//	}
//	
//	public class PortReply {
//
//		public PortReplySpecifics[] port_reply;
//		
//		public PortReply() {
//			// nothing for the moment
//		}
//	}
}
