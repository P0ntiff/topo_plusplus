package net.floodlightcontroller.linkverifier;

import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import net.floodlightcontroller.core.IFloodlightProviderService;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.routing.Link;

public class InternalStatisticsGetter extends Thread {

    protected IFloodlightProviderService provider;

    private Link link;
    private IOFSwitch sw1;
    private IOFSwitch sw2;

    protected static Logger log;
     
    public InternalStatisticsGetter(Link link, IFloodlightProviderService floodlightProvider) {
    	log = LoggerFactory.getLogger(InternalStatisticsGetter.class);
    	
        this.provider = floodlightProvider;

        this.link = link;
       	this.sw1 = provider.getSwitch(link.getSrc());
       	this.sw2 = provider.getSwitch(link.getDst());

	}

    public void run() {

	log.warn("\n\n-- STATS for (switch,port) pairs ({}, {}) and ({}, {}) --\n",
			new Object[] {sw1.getStringId(),
				link.getSrcPort(),
				sw2.getStringId(),
				link.getDstPort(),
				});

        OFPortStatisticsReply sw1Stats = (OFPortStatisticsReply)getPortStatistics(sw1, link.getSrcPort()).get(0);
	    OFPortStatisticsReply sw2Stats = (OFPortStatisticsReply)getPortStatistics(sw2, link.getDstPort()).get(0);

	log.warn("\n({}, {}): received {}B, transmitted {}B.\n",
			new Object[] {sw1.getStringId(),
				sw1Stats.getPortNumber(),
				sw1Stats.getReceiveBytes(),
				sw1Stats.getTransmitBytes(),
			});
	log.warn("\n({}, {}): received {}B, transmitted {}B.\n",
			new Object[] {sw2.getStringId(),
				sw2Stats.getPortNumber(),
				sw2Stats.getReceiveBytes(),
				sw2Stats.getTransmitBytes(),
			});

        return;
    }

    public List<OFStatistics> getPortStatistics(IOFSwitch sw, short port) {

        Future<List<OFStatistics>> future;
        List<OFStatistics> values = null;
        OFStatisticsRequest req = new OFStatisticsRequest();
        req.setStatisticType(OFStatisticsType.PORT);
        int requestLength = req.getLengthU();
        if (sw == null) return null;

        // Construct Port Req
        OFPortStatisticsRequest portReq = new OFPortStatisticsRequest();
        portReq.setPortNumber(port);
        req.setStatistics(Collections.singletonList((OFStatistics)portReq));
        requestLength += portReq.getLength();
        req.setLengthU(requestLength);
        try {
            future = sw.queryStatistics(req);
            values = future.get(1, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("Failure retrieving statistics from switch " + sw, e);
        }
        return values;
    }

}
