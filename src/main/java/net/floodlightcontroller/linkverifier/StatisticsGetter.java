package net.floodlightcontroller.linkverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFPacketIn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.LLDP;

public class StatisticsGetter extends Thread {
	
	private final String ipAddress = "localhost";
	private final String port = "8080";
	
	//maps a Switch, to a collection of its ports and associated links
	private Map<String, Map<Integer, StatLink>> switchMap = new HashMap<String, Map<Integer, StatLink>>();

	private LLDP lldp;
	private IOFSwitch sw;
	private OFPacketIn msg;
	private FloodlightContext cntx;
	
	protected static Logger log;
	
	public StatisticsGetter(LLDP lldp, IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		this.lldp = lldp;
		this.sw = sw;
		this.msg = msg;
		this.cntx = cntx;
		log = LoggerFactory.getLogger(StatisticsGetter.class);
	}
	
	public void run() {
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
			return;
		} 
		log.warn("\n\n\n Verifying switch {}\n\n\n", l.src_switch);
		try {
			//log.warn("\n{}", l.toString());
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
			//log.warn("\n{}", l.toString());

			//TODO this is only one flow direction, we should also consider the other direction (ie, dst -> src)
			
			
			//TODO set threshhold, 1000 is giga arbitrary
			if(Math.abs(srcPort.transmitBytes - dstPort.receiveBytes) > 1000) {
				log.warn("SUSPICIOUS LINK STATISTICS, DIFFERENCE OF {}", Math.abs(srcPort.transmitBytes - dstPort.receiveBytes));
			} 

		} catch (Exception e) {
			log.warn("ERROR: verify_lldp_link {}", e);
		}
		return;
	}
	
	public BufferedReader makeWebRequest(String path) throws IOException {
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

}