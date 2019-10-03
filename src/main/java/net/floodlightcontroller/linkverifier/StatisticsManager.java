package net.floodlightcontroller.linkverifier;

import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.statistics.OFPortStatisticsReply;

import net.floodlightcontroller.packet.LLDP;

public class StatisticsManager extends Thread {
	
	private boolean running;
	
	//TODO maybe add data structures to store the latest statistics data

    public void run() {
    	running = true;
    	
    	while (running) {
    		try {
				Thread.sleep(1000); // run every 1 second
			} catch (InterruptedException e) {
				running = false;
				continue;
			}
    		
    		new StatisticsGetter().start();
    	}
    	
    }
    
    public void stop() {
    	running = false;
    }
}
