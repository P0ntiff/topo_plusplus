package net.floodlightcontroller.linkverifier;


import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;


import javafx.util.Pair;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.linkverifier.InternalStatisticsGetter;

import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.routing.Link;

enum analysisMethod {
	STRICT,
	LOSSY,
	ADAPTIVE
}

public class StatisticsManager extends Thread {
	
	ILinkDiscoveryService linkEngine;
	IFloodlightProviderService provider;

	protected static Logger log;
	
	private boolean running;

	private analysisMethod selectedMethod = analysisMethod.LOSSY;

	//  record benign link latencies
	private ConcurrentLinkedQueue<Long> LinkLoss = new ConcurrentLinkedQueue<Long>();

	//TODO maybe add data structures to store the latest statistics data
	
	public StatisticsManager(ILinkDiscoveryService linkEngine, IFloodlightProviderService floodlightProvider) {
		this.linkEngine = linkEngine;
		provider = floodlightProvider;
		log = LoggerFactory.getLogger(StatisticsManager.class);
	}

    public void run() {
    	running = true;

    	InternalStatisticsGetter stats = new InternalStatisticsGetter(provider);

        Map<String, ArrayList<Long>> linkPackets = new HashMap<>();

    	while (running) {
    		try {
				Thread.sleep(5000); // run every 5 seconds
			} catch (InterruptedException e) {
				running = false;
				continue;
			}


    		for (Link link : linkEngine.getLinks().keySet()) {

				StringBuilder infoOutput = new StringBuilder();
				StringBuilder warnOutput = new StringBuilder();

				Boolean hasWarning = false;

				IOFSwitch sw1 = provider.getSwitch(link.getSrc());
				IOFSwitch sw2 = provider.getSwitch(link.getDst());

				List<OFPortStatisticsReply> linkstats = stats.getLinkStatistics(link);

				OFPortStatisticsReply sw1Stats = linkstats.get(0);
				OFPortStatisticsReply sw2Stats = linkstats.get(1);

				String linkKey = link.toKeyString();
				long sent = sw1Stats.getTransmitBytes();
				long recv = sw2Stats.getReceiveBytes();

				long prevSent = 0;
				long prevRecv = 0;


					if (linkPackets.containsKey(linkKey)) {
						ArrayList<Long> previous = linkPackets.get(linkKey);
						prevSent = previous.get(0);
						prevRecv = previous.get(1);
						previous.set(0, sent);
						previous.set(1, recv);

					} else {
						linkPackets.put(linkKey, new ArrayList<>(Arrays.asList(sent, recv)));
					}



				infoOutput.append(String.format("\n\n-- STATS for (%s/%s - %s/%s) link --\n",
						addrFormat(sw1.getStringId()),link.getSrcPort(), addrFormat(sw2.getStringId()), link.getDst()));

				infoOutput.append(String.format("(%s, %s): transmitted %sB.\n",
						sw1.getStringId(), sw1Stats.getPortNumber(), sent));

				infoOutput.append(String.format("(%s, %s): received %sB.\n",
						sw2.getStringId(), sw2Stats.getPortNumber(), recv));

				long diffSent = (sent - prevSent);
				long diffRecv = (recv - prevRecv);
				long difference = diffSent - diffRecv;

				boolean triggerWarning = false;


				if(selectedMethod == analysisMethod.STRICT){
					if(Math.abs(difference) > 0 ){
						triggerWarning = true;
					}
				} else if(selectedMethod == analysisMethod.LOSSY) {
					if(Math.abs(difference) - 200 > ((diffSent + diffRecv) * 0.1)){
						triggerWarning = true;
					}
				} else if(selectedMethod == analysisMethod.ADAPTIVE) {
					//TODO
					long loss = Math.abs(difference);

					if(LinkLoss.size() <  linkEngine.getLinks().size() * 1) {
						LinkLoss.add(Math.abs(difference));
						log.info("The link lost is " + loss);

					}

					else {
						long q1_score = quartile(LinkLoss, 25);
						long q3_score = quartile(LinkLoss, 75);
						long iqr = q3_score - q1_score;
						long threshold = q3_score + 3 * iqr;


						if(loss > threshold) {
							log.error(String.format("WARNING: Link (%s/%s -> %s/%s) has abnormal loss - loss: %d B threshold: %d B",
									addrFormat(sw1.getStringId()), link.getSrcPort(), addrFormat(sw2.getStringId()), link.getDst(),
									loss, threshold));
						}
						else {
							log.info(String.format("Link (%s/%s -> %s/%s) is within normal bounds - loss: %d B threshold: %d B",
									addrFormat(sw1.getStringId()), link.getSrcPort(), addrFormat(sw2.getStringId()), link.getDst(),
									loss, threshold));
							LinkLoss.add(loss);
						}

					}
				}

				LinkInfo linkInfo = linkEngine.getLinks().get(link);
				if (triggerWarning) {
					warnOutput.append(String.format("WARNING: Link (%s/%s -> %s/%s) has inconsistent packets - %d sent vs %d received, since last round.",
							addrFormat(sw1.getStringId()), link.getSrcPort(), addrFormat(sw2.getStringId()), link.getDst(),
							diffSent, diffRecv));
					hasWarning = true;
					if (linkInfo != null) {
						linkInfo.setStatsVerifiedStatus(false);
					}
				} else {
					infoOutput.append("OKAY: SW1 received matches SW2 transmitted\n");
					if (linkInfo != null) {
						linkInfo.setStatsVerifiedStatus(true);
					}
				}

				if(hasWarning) {
					log.warn(warnOutput.toString());
				} else {
					// Don't spam console
//					log.info(String.format("Link (%s/%s -> %s/%s) consistent.",
//							addrFormat(sw1.getStringId()),link.getSrcPort(), addrFormat(sw2.getStringId()), link.getDst()
//							));
				}

    		}
    	}
    	
    }

	//Retrieve the quartile value from an array
	private static long quartile(Queue<Long> q, long lowerPercent) {

		if (q == null || q.size() == 0) {
			throw new IllegalArgumentException("The data array either is null or does not contain any data.");
		}

		ArrayList<Long> list = new ArrayList<Long>(q);

		Collections.sort(list);

		int n = (int) Math.round(list.size() * lowerPercent / 100);

		return list.get(n);

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
