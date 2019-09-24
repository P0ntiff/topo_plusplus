package net.floodlightcontroller.linkverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.routing.Link;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.OFPortStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.LLDP;

public class InternalStatisticsGetter extends Thread {

    private LLDP lldp;
    private IOFSwitch sw;
    private short inPort;
    private OFPacketIn msg;
    private FloodlightContext cntx;
    protected IFloodlightProviderService provider;

    protected static Logger log;

    public InternalStatisticsGetter(LLDP lldp, IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx, IFloodlightProviderService floodlightProvider) {
        this.lldp = lldp;
        this.sw = sw;
        this.msg = msg;
        this.inPort = msg.getInPort();
        this.cntx = cntx;
        this.provider = floodlightProvider;
        log = LoggerFactory.getLogger(StatisticsGetter.class);
    }

    public void run() {
        List<OFStatistics> sw1Stats = getPortStatistics(sw, inPort);
        log.warn("\n\n Retrieved {} from sw1 \n\n", sw1Stats.size());
        return;
    }

    //***********************************
    //  TOPOGUARD++ METHODS - Statistics and Flow Conservation
    //***********************************



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
            values = future.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("Failure retrieving statistics from switch " + sw, e);
        }
        return values;
    }

}