[1mdiff --git a/build.xml b/build.xml[m
[1mindex bed6c60..038c949 100644[m
[1m--- a/build.xml[m
[1m+++ b/build.xml[m
[36m@@ -44,8 +44,8 @@[m
     <property name="floodlight-test-jar" location="${target}/floodlight-test.jar"/>[m
     <property name="thrift.dir" value="${basedir}/src/main/thrift"/>[m
     <property name="thrift.out.dir" value="lib/gen-java"/>[m
[31m-    <property name="ant.build.javac.source" value="1.6"/>[m
[31m-    <property name="ant.build.javac.target" value="1.6"/>[m
[32m+[m[32m    <property name="ant.build.javac.source" value="1.7"/>[m
[32m+[m[32m    <property name="ant.build.javac.target" value="1.7"/>[m
     <property name="findbugs.home" value="../build/findbugs-2.0.2"/>[m
     <property name="findbugs.results" value="findbugs-results" />[m
     <property name="lib" location="lib"/>[m
[1mdiff --git a/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java b/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java[m
[1mindex eb29731..4d0f447 100644[m
[1m--- a/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java[m
[1m+++ b/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java[m
[36m@@ -998,9 +998,8 @@[m [mpublic class LinkDiscoveryManager implements IOFMessageListener,[m
         // Get statistics[m
         log.error("\n STAT GATHER TEST \n");[m
         List<OFStatistics> iofStats = getPortStatistics(iofSwitch, inPort);[m
[31m-	    log.warn("Port Statistics: {}", iofStats);[m
[31m-        List<OFStatistics> remoteStats = getPortStatistics(remoteSwitch, remotePort);[m
[31m-        log.error("\n STAT GATHER TEST 2 \n" + remoteStats);[m
[32m+[m	[32m    log.warn("Collected {} Statistics: ", iofStats.size());[m
[32m+[m[41m [m
 [m
         // Consume this message[m
         ctrLldpEol.updateCounterNoFlush();[m
[36m@@ -2654,7 +2653,7 @@[m [mpublic class LinkDiscoveryManager implements IOFMessageListener,[m
     //***************[m
     // Statistics [GUARD++][m
     //***************[m
[31m-    public List<OFStatistics> getPortStatistics(IOFSwitch sw, int port) {[m
[32m+[m[32m    public List<OFStatistics> getPortStatistics(IOFSwitch sw, short port) {[m
         Future<List<OFStatistics>> future;[m
         List<OFStatistics> values = null;[m
         OFStatisticsRequest req = new OFStatisticsRequest();[m
[1mdiff --git a/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java~ b/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java~[m
[1mindex b5398fa..a1418a4 100644[m
[1m--- a/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java~[m
[1m+++ b/src/main/java/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.java~[m
[36m@@ -45,6 +45,7 @@[m [mimport java.util.Set;[m
 import java.util.concurrent.BlockingQueue;[m
 import java.util.concurrent.ConcurrentHashMap;[m
 import java.util.concurrent.ConcurrentLinkedQueue;[m
[32m+[m[32mimport java.util.concurrent.Future;[m
 import java.util.concurrent.LinkedBlockingQueue;[m
 import java.util.concurrent.ScheduledExecutorService;[m
 import java.util.concurrent.TimeUnit;[m
[36m@@ -114,9 +115,13 @@[m [mimport org.openflow.protocol.OFPacketOut;[m
 import org.openflow.protocol.OFPhysicalPort;[m
 import org.openflow.protocol.OFPhysicalPort.OFPortState;[m
 import org.openflow.protocol.OFPort;[m
[32m+[m[32mimport org.openflow.protocol.OFStatisticsRequest;[m
 import org.openflow.protocol.OFType;[m
 import org.openflow.protocol.action.OFAction;[m
 import org.openflow.protocol.action.OFActionOutput;[m
[32m+[m[32mimport org.openflow.protocol.statistics.OFPortStatisticsRequest;[m
[32m+[m[32mimport org.openflow.protocol.statistics.OFStatistics;[m
[32m+[m[32mimport org.openflow.protocol.statistics.OFStatisticsType;[m
 import org.openflow.util.HexString;[m
 import org.slf4j.Logger;[m
 import org.slf4j.LoggerFactory;[m
[36m@@ -991,11 +996,10 @@[m [mpublic class LinkDiscoveryManager implements IOFMessageListener,[m
         removeFromMaintenanceQueue(nptDst);[m
 [m
         // Get statistics[m
[31m-        List<OFStatistics> iofStats = getPortStatistics(iofSwitch, inPort);[m
[31m-	log.warn("Port Statistics: {}", iofStats);[m
         log.error("\n STAT GATHER TEST \n");[m
[31m-        List<OFStatistics> remoteStats = getPortStatistics(remoteSwitch, remotePort);[m
[31m-        log.error("\n STAT GATHER TEST 2 \n");[m
[32m+[m[32m        List<OFStatistics> iofStats = getPortStatistics(iofSwitch, inPort);[m
[32m+[m	[32m    log.warn("Collected {} Statistics: ", iofStats.size());[m
[32m+[m[41m [m
 [m
         // Consume this message[m
         ctrLldpEol.updateCounterNoFlush();[m
[36m@@ -2647,16 +2651,21 @@[m [mpublic class LinkDiscoveryManager implements IOFMessageListener,[m
     }[m
 [m
     //***************[m
[31m-    // Statistics[m
[32m+[m[32m    // Statistics [GUARD++][m
     //***************[m
     public List<OFStatistics> getPortStatistics(IOFSwitch sw, int port) {[m
         Future<List<OFStatistics>> future;[m
         List<OFStatistics> values = null;[m
[31m-        OFPortStatisticsRequest req = new OFPortStatisticsRequest();[m
[31m-        // Construct Req[m
[31m-        req.setPortNumber(port);[m
[31m-        req.setStatistics(Collections.singletonList((OFStatistics) req));[m
[31m-        requestLength += specificReq.getLength();[m
[32m+[m[32m        OFStatisticsRequest req = new OFStatisticsRequest();[m
[32m+[m[32m        req.setStatisticType(OFStatisticsType.PORT);[m
[32m+[m[32m        int requestLength = req.getLengthU();[m
[32m+[m[32m        if (sw == null) return values;[m
[32m+[m
[32m+[m[32m        // Construct Port Req[m
[32m+[m[32m        OFPortStatisticsRequest portReq = new OFPortStatisticsRequest();[m
[32m+[m[32m        portReq.setPortNumber(port);[m
[32m+[m[32m        req.setStatistics(Collections.singletonList((OFStatistics)portReq));[m
[32m+[m[32m        requestLength += portReq.getLength();[m
         req.setLengthU(requestLength);[m
         try {[m
             future = sw.queryStatistics(req);[m
[36m@@ -2664,6 +2673,7 @@[m [mpublic class LinkDiscoveryManager implements IOFMessageListener,[m
         } catch (Exception e) {[m
             log.error("Failure retrieving statistics from switch " + sw, e);[m
         }[m
[32m+[m
         return values;[m
     }[m
 }[m
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$1.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$1.class[m
[1mindex 098150e..366f3d9 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$1.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$1.class differ
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$2.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$2.class[m
[1mindex b3ac7a0..78488b3 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$2.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$2.class differ
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$DirectLinkEvent.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$DirectLinkEvent.class[m
[1mindex 62f9310..0944253 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$DirectLinkEvent.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$DirectLinkEvent.class differ
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$HAListenerDelegate.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$HAListenerDelegate.class[m
[1mindex fdb7fd1..7cff4ab 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$HAListenerDelegate.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$HAListenerDelegate.class differ
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$MACRange.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$MACRange.class[m
[1mindex e8ce03a..8916202 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$MACRange.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$MACRange.class differ
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$QuarantineWorker.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$QuarantineWorker.class[m
[1mindex 7d8dd78..9f98679 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$QuarantineWorker.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager$QuarantineWorker.class differ
[1mdiff --git a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.class b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.class[m
[1mindex fdfa654..4fa79c2 100644[m
Binary files a/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.class and b/target/bin/net/floodlightcontroller/linkdiscovery/internal/LinkDiscoveryManager.class differ
[1mdiff --git a/target/bin/org/openflow/protocol/statistics/OFTableStatistics.class b/target/bin/org/openflow/protocol/statistics/OFTableStatistics.class[m
[1mindex eba7b51..ba322ea 100644[m
Binary files a/target/bin/org/openflow/protocol/statistics/OFTableStatistics.class and b/target/bin/org/openflow/protocol/statistics/OFTableStatistics.class differ
[1mdiff --git a/target/floodlight-test.jar b/target/floodlight-test.jar[m
[1mindex a2d9672..f164ccd 100644[m
Binary files a/target/floodlight-test.jar and b/target/floodlight-test.jar differ
[1mdiff --git a/target/floodlight.jar b/target/floodlight.jar[m
[1mindex a49279e..20d5d93 100644[m
Binary files a/target/floodlight.jar and b/target/floodlight.jar differ
