package net.floodlightcontroller.linkverifier;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.hash.HashCode;
import javafx.concurrent.Worker;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.util.MACAddressTest;
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
    public static final String MODULE_NAME = "hiddenpacketverifier";
    protected IFloodlightProviderService floodlightProvider;
    protected static Logger log;
    //stores the hash of a packet payload with the time it was sent into the system
    private ConcurrentHashMap<Integer, Long> sentPackets = new ConcurrentHashMap<Integer, Long>();

    protected List<Ethernet> storedPackets = new ArrayList<>();

    String srcMAC = "aa:aa:aa:aa:aa:aa";


//- - -

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                //only care about data plane messages
                if (eth.getEtherType() == Ethernet.TYPE_IPv4) {

                    //is this the hidden packet
                    if(srcMAC.equals(eth.getSourceMAC())) {

                        if(sentPackets.containsKey(eth.getPayload().hashCode())) {
                            Long timeSent = sentPackets.get(eth.getPayload().hashCode());
                            log.warn("Received HPV sent @ {}, received @ {}", timeSent, System.nanoTime());
                        } else {
                            return Command.STOP;
                        }

                    } else {
                        storedPackets.add(eth); //maybe do this in a different data structure for efficiency
                        log.info("Adding new to {} stored pkt", storedPackets.size());
                        (new Thread(new PacketWorker(sw))).start();
                    }


                }
                break;
            default:
                break;
        }

        return Command.CONTINUE;
    }

    public OFPacketOut generate_packet_out(Ethernet eth){

        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage((OFType.PACKET_OUT));
        byte[] originalSrc = eth.getSourceMACAddress();
        byte[] data = eth.serialize();
        po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        po.setInPort(OFPort.OFPP_NONE);
        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + data.length);
        po.setPacketData(data);
        return po;
    }



    // Nested Class
    protected class PacketWorker implements Runnable {
        IOFSwitch sw;

        public PacketWorker(IOFSwitch switchID) {sw = switchID;}

        @Override
        public void run() {
            if (sw == null) return; //switch is offline, do nothing
            if(storedPackets.isEmpty()) return;
            Ethernet eth = storedPackets.remove(0);
            eth.setSourceMACAddress(srcMAC);
            OFPacketOut po = generate_packet_out(eth);

            if(po == null) {
                log.warn("No stored packet in HPV");
                return;
            }

            try {
                sw.write(po, null);
                sw.flush();
                log.info("HPV SENT INTO SYSTEM");
                sentPackets.put((eth.getPayload()).hashCode(), System.nanoTime());
                //start a time out for another packet in
                Thread.sleep(500); //wait

                if(sentPackets.containsKey(eth.getPayload().hashCode())){
                    log.warn("HPV NOT RETURNED IN 500MS");
                } else {
                    log.warn("HPV RETURNED IN <500MS");
                }

            } catch (Exception e) {
                log.error("Cannot write probing message to SW " + sw.getStringId());
            }
        }
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
