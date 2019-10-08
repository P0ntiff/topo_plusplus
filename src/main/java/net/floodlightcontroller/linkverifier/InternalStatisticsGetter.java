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

public class InternalStatisticsGetter {

    protected IFloodlightProviderService provider;

    protected static Logger log;
     
    public InternalStatisticsGetter(IFloodlightProviderService floodlightProvider) {
    	log = LoggerFactory.getLogger(InternalStatisticsGetter.class);
        this.provider = floodlightProvider;

	}

    /**
     * Returns a list (length = 2) of statistics associated with link
     * Statistics come from ports at either end of link
     *
     * @author jaric.thorning
     * @param link
     * @return
     */
	public List<OFPortStatisticsReply> getLinkStatistics(Link link) {

        List<OFPortStatisticsReply> returnStats = new ArrayList<OFPortStatisticsReply>();

        IOFSwitch sw1 = provider.getSwitch(link.getSrc());
        IOFSwitch sw2 = provider.getSwitch(link.getDst());

        OFPortStatisticsReply sw1Stats = (OFPortStatisticsReply)getPortStatistics(sw1, link.getSrcPort()).get(0);
        OFPortStatisticsReply sw2Stats = (OFPortStatisticsReply)getPortStatistics(sw2, link.getDstPort()).get(0);

        returnStats.add(sw1Stats);
        returnStats.add(sw2Stats);

        return returnStats;
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
