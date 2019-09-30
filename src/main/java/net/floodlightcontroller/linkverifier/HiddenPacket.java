package net.floodlightcontroller.linkverifier;


import java.util.*;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.topology.NodePortTuple;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/** HiddenPacket thread to send HP to desired switches
 *
**/
public class HiddenPacket extends Thread {
    protected IFloodlightProviderService provider;
    protected static Logger log;

    //host map, K = Switch/Port Pair, V = Host_IP
    private Map<NodePortTuple,Integer> deviceMap;
    private Map<Integer, List<String>> packetMap;
    private NodePortTuple startPoint;
    private NodePortTuple endPoint;
    private int endIPAddr;


    public HiddenPacket(IFloodlightProviderService provider,
                        Map<NodePortTuple,Integer> deviceMap,
                        Map<Integer, List<String>> packetMap) {
        log = LoggerFactory.getLogger(HiddenPacket.class);
        this.provider = provider;
        this.deviceMap = deviceMap;
        this.packetMap = packetMap;
        this.startPoint = startPoint;
        this.endPoint = endPoint;
        this.endIPAddr = endIPAddr;

    }

    public void run() {

        //send the packet into the system
        IOFSwitch sw = provider.getSwitch(startPoint.getNodeId());
        if (sw == null) return; //switch is offline, do nothing

        //just PING for the moment, but should be changed
        IPacket packet = new IPv4()
                .setProtocol(IPv4.PROTOCOL_ICMP)
                .setSourceAddress("10.0.0.100")
                .setDestinationAddress(deviceMap.get(endPoint))
                .setPayload(new ICMP()
                        .setIcmpType((byte) 8)
                        .setIcmpCode((byte) 0)
                        .setPayload(new Data(new byte[]
                                {0x76, (byte) 0xf2, 0x0, 0x2, 0x1, 0x1, 0x1}))
                );

        //not sure how next hop works for controller
        Ethernet eth = new Ethernet().setSourceMACAddress("aa:aa:aa:aa:aa:aa")
                .setDestinationMACAddress("bb:bb:bb:bb:bb:bb")
                .setEtherType(Ethernet.TYPE_IPv4);

        eth.setPayload(packet);
        OFPacketOut po = generate_packet_out(eth);

        try {
            sw.write(po, null);
            sw.flush();
            log.info("HPV SENT INTO SYSTEM {}", (eth.getPayload()).hashCode());
            Thread.sleep(500);

            if(packetMap.containsKey(eth.getPayload().hashCode())){
                log.warn("HPV WAS NOT RETURNED IN 500ms");
            } else {
                log.warn("HPV WAS RETURNED IN 500ms");
            }

        } catch (Exception e) {
            log.error("Cannot write probing message to SW " + sw.getStringId());
        }
        return;
    }



    public OFPacketOut generate_packet_out(Ethernet eth){

        OFPacketOut po = (OFPacketOut) provider.getOFMessageFactory().getMessage((OFType.PACKET_OUT));
        byte[] data = eth.serialize();

        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue(),
                (short)0xFFFF));

        po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        po.setInPort(OFPort.OFPP_NONE);
        po.setPacketData(data);
        po.setActions(actions);
        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

        // set data and data length
        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length + po.getActionsLength() );

        return po;
    }



}