package net.floodlightcontroller.linkverifier;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class StatisticsManager extends Thread {
	
	ILinkDiscoveryService linkEngine;
	IFloodlightProviderService provider;
	
	private boolean running;
	
	//TODO maybe add data structures to store the latest statistics data
	
	public StatisticsManager(ILinkDiscoveryService linkEngine, IFloodlightProviderService floodlightProvider) {
		this.linkEngine = linkEngine;
		provider = floodlightProvider;
	}

    public void run() {
    	running = true;
    	
    	while (running) {
    		try {
				Thread.sleep(5000); // run every 5 seconds
			} catch (InterruptedException e) {
				running = false;
				continue;
			}
    		
    		for (Link link : linkEngine.getLinks().keySet()) { 
    			new InternalStatisticsGetter(link, provider).start();
    		}
    	}
    	
    }
    
    public void kill() {
    	running = false;
    }
}
