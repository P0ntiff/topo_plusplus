package net.floodlightcontroller.linkverifier;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import javafx.concurrent.Worker;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.virtualnetwork.IVirtualNetworkService;
import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;


/*
 * TOPOGUARD++ CLASS FOR VERIFICATION OF FLOW BETWEEN LINKS
 */
public class HiddenPacket implements IOFMessageListener, IFloodlightModule<IFloodlightService> {

    // Instance Variables
    protected IFloodlightProviderService floodlightProvider;
    protected static Logger log;
    public static final String MODULE_NAME = "hiddenpacketverifier";
    protected List<Ethernet> storedPackets = new ArrayList<>();
//- - -

// Nested Class
    protected class PacketWorker implements Runnable {
        IOFSwitch sw;
        short portID;
        int delay;

        public PacketWorker(IOFSwitch s, short p, int d){
            sw = s;
            portID = p;
            delay = d;
        }

        @Override
        public void run() {
            if (sw == null) return; //switch is offline, do nothing

            OFPacketOut po = generate_packet(sw, portID);

            log.info("Send out delay probe message, isEmpty {}", ((LearningSwitch)sw).getTable().size());
            try {
                if (delay > 0) {
                    Thread.sleep(delay);
                }
                sw.write(po, null);
                sw.flush();
            } catch (Exception e) {
                log.error("Cannot write probing message to SW " + sw.getStringId());
            }
        }
    }


    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

                //only care about data plane messages
                if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
                    storedPackets.add(eth); //maybe do this in a different data structure for efficiency
                    log.info("{} stored packets", storedPackets.size());
                    log.info("\n\nTEST LEARNINGSWITCH isEmpty {}\n\n", ((LearningSwitch)sw).getTable().size());
                    return Command.CONTINUE;
                    //(new Thread(new PacketWorker(sw, ((OFPacketIn) msg).getInPort(), 500))).start();
                }
                break;
            default:
                break;
        }

        return Command.CONTINUE;
    }


    public boolean remove_switch_pkt_rule(){
        //get the end point and remove its flow rules for the packet
        return true;

    }

    public OFPacketOut generate_packet(IOFSwitch sw, short port){

        Ethernet eth = storedPackets.remove(0);
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage((OFType.PACKET_OUT));
        byte[] data = eth.serialize();

        po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        po.setInPort(OFPort.OFPP_NONE);
        // set data and data length
        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length);
        po.setPacketData(data);
        return po;

    }


        //***************
        // IFloodlightModule
        //***************
        @Override
        public String getName () {
            return MODULE_NAME;
        }

        @Override
        public void init (FloodlightModuleContext cntx) throws FloodlightModuleException {
            floodlightProvider = cntx.getServiceImpl(IFloodlightProviderService.class);
            log = LoggerFactory.getLogger(LinkVerifier.class);
        }

        @Override
        public void startUp (FloodlightModuleContext arg0) throws FloodlightModuleException {
            // OpenFlow messages we want to receive
            floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        }

        @Override
        public Collection<Class<? extends IFloodlightService>> getModuleDependencies () {
            Collection<Class<? extends IFloodlightService>> l =
                    new ArrayList<Class<? extends IFloodlightService>>();
            l.add(IFloodlightProviderService.class);
            return l;
        }

        @Override
        public Collection<Class<? extends IFloodlightService>> getModuleServices () {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls () {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isCallbackOrderingPrereq (OFType type, String name){
            return (type.equals(OFType.PACKET_IN) && name.equals("linkdiscovery"));
        }

        @Override
        public boolean isCallbackOrderingPostreq (OFType type, String name){
            return false;
        }

    }
