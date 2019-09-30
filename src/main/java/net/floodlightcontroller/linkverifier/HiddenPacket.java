package net.floodlightcontroller.linkverifier;


import java.util.*;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.topology.NodePortTuple;
import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionType;
import org.openflow.util.U16;
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


    public HiddenPacket(IFloodlightProviderService provider,
                        Map<NodePortTuple,Integer> deviceMap,
                        Map<Integer, List<String>> packetMap,
                        NodePortTuple startPoint, NodePortTuple endPoint) {
        log = LoggerFactory.getLogger(HiddenPacket.class);
        this.provider = provider;
        this.deviceMap = deviceMap;
        this.packetMap = packetMap;
        this.startPoint = startPoint;
        this.endPoint = endPoint;
    }

    public void run() {

        IOFSwitch srcSw = provider.getSwitch(startPoint.getNodeId());
        IOFSwitch dstSw = provider.getSwitch(endPoint.getNodeId());

        if (srcSw == null || dstSw == null) {
            log.warn("Switch on path is offline");
            return; //switch is offline, do nothing
        }

        Ethernet eth = generate_payload();
        OFPacketOut po = generate_packet_out(eth);
        OFMessage flowMod = generate_flow_rule((IPv4)eth.getPayload());

        try {
            //INSTALL FLOW RULE IN END POINT
            dstSw.write(flowMod, null);
            dstSw.flush();

            //SEND HIDDEN PACKET INTO SYSTEM

            srcSw.write(po, null);
            srcSw.flush();
            log.info("HP SENT INTO SYSTEM {}", (eth.getPayload()).hashCode());
            Thread.sleep(500);

            if(packetMap.containsKey(eth.getPayload().hashCode())){
                log.warn("HP WAS NOT RETURNED IN 500ms");
            } else {
                log.warn("HP WAS RETURNED IN 500ms");
            }

        } catch (Exception e) {
            log.error("Cannot write probing message to SW " + srcSw.getStringId());
        }
        return;
    }

    public Ethernet generate_payload(){
        //just PING for the moment, but should randomly select payload type
        IPacket packet = new IPv4()
                .setProtocol(IPv4.PROTOCOL_ICMP)
                .setSourceAddress(deviceMap.get(startPoint))
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
        return eth;
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

    public OFMessage generate_flow_rule(IPv4 packet){
        //TODO this port should be changed when shortest route is figured out
        OFMatch match = new OFMatch().loadFromPacket(packet.serialize(), OFPort.OFPP_ALL.getValue());

        List<OFAction> actions = new ArrayList<>();
        actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

        OFMessage flowMod = ((OFFlowMod) provider.getOFMessageFactory().getMessage(OFType.FLOW_MOD))
                .setMatch(match).setCommand(OFFlowMod.OFPFC_ADD)
                .setOutPort(OFPort.OFPP_NONE)
                .setActions(actions)
                .setHardTimeout((short)5) //timeout rule after 5 seconds
                .setPriority((short)1).setLength(U16.t(OFFlowMod.MINIMUM_LENGTH));
        return flowMod;
    }

}