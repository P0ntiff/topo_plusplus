package net.floodlightcontroller.linkverifier;


import java.util.*;


import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.linkverifier.InternalStatisticsGetter;

import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.routing.Link;


public class StatisticsManager extends Thread {
	
	ILinkDiscoveryService linkEngine;
	IFloodlightProviderService provider;

	protected static Logger log;
	
	private boolean running;
	
	//TODO maybe add data structures to store the latest statistics data
	
	public StatisticsManager(ILinkDiscoveryService linkEngine, IFloodlightProviderService floodlightProvider) {
		this.linkEngine = linkEngine;
		provider = floodlightProvider;
		log = LoggerFactory.getLogger(StatisticsManager.class);
	}

    public void run() {
    	running = true;

    	InternalStatisticsGetter stats = new InternalStatisticsGetter(provider);




    	while (running) {
    		try {
				Thread.sleep(5000); // run every 5 seconds
			} catch (InterruptedException e) {
				running = false;
				continue;
			}


    		for (Link link : linkEngine.getLinks().keySet()) {

				StringBuilder warningOutput = new StringBuilder();

				IOFSwitch sw1 = provider.getSwitch(link.getSrc());
				IOFSwitch sw2 = provider.getSwitch(link.getDst());

				List<OFPortStatisticsReply> linkstats = stats.getLinkStatistics(link);

				OFPortStatisticsReply sw1Stats = linkstats.get(0);
				OFPortStatisticsReply sw2Stats = linkstats.get(1);

//				warningOutput.append(String.format("\n\n-- STATS for (switch,port) pairs (%s, %s) and (%s, %s) --\n",
//						sw1.getStringId(), link.getSrcPort(), sw2.getStringId(), link.getDstPort()));

				warningOutput.append(String.format("\n\n-- STATS for (%s/%s - %s/%s) link --\n",
						addrFormat(sw1.getStringId()),link.getSrcPort(), addrFormat(sw2.getStringId()), link.getDst()));

				warningOutput.append(String.format("(%s, %s): received %sB, transmitted %sB.\n",
						sw1.getStringId(), sw1Stats.getPortNumber(), sw1Stats.getReceiveBytes(),
						sw1Stats.getTransmitBytes()));

				warningOutput.append(String.format("(%s, %s): received %sB, transmitted %sB.\n",
						sw2.getStringId(), sw2Stats.getPortNumber(), sw2Stats.getReceiveBytes(),
						sw2Stats.getTransmitBytes()));

				if(sw1Stats.getReceiveBytes() != sw2Stats.getTransmitBytes()){
					warningOutput.append("WARNING: SW1 received DOES NOT match SW2 transmitted\n");
				} else{
					warningOutput.append("OKAY: SW1 received matches SW2 transmitted\n");
				}

				if(sw2Stats.getReceiveBytes() != sw1Stats.getTransmitBytes()){
					warningOutput.append("WARNING: SW2 received DOES NOT match SW1 transmitted\n");
				} else{
					warningOutput.append("OKAY: SW2 received matches SW1 transmitted\n");
				}


				log.warn(warningOutput.toString());

    		}
    	}
    	
    }

    private String addrFormat(String addr){
		StringBuilder formattedAddr = new StringBuilder();
		int index = 0;

		for( char c : addr.toCharArray()){
			if(c == ':'){
				index++;
			} else if(c == '0'){
				index++;
			} else{
				break;
			}
		}

		if(index != 0) {
			formattedAddr.append("::");

			for (int i = index; i < addr.length(); i++) {
				formattedAddr.append((addr.charAt(i)));
			}
		} else{
			formattedAddr.append("::00");
		}

		return formattedAddr.toString();
	}
    
    public void kill() {
    	running = false;
    }
}
