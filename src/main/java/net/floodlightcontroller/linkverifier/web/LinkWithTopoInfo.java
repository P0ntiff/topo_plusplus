/**
 *    Copyright 2013, Big Switch Networks, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.linkverifier.web;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LinkDirection;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LinkType;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.routing.Link;
import org.openflow.util.HexString;

import java.io.IOException;

/**
 * This class is both the datastructure and the serializer
 * for a link with the corresponding type of link.
 * @author alexreimers
 */
@JsonSerialize(using= LinkWithTopoInfo.class)
public class LinkWithTopoInfo extends JsonSerializer<LinkWithTopoInfo> {
    public long srcSwDpid;
    public short srcPort;
    public long dstSwDpid;
    public short dstPort;
    public long lastLldpReceivedTime;
    public long currentKnownDelay;
    public long lastHpvReceivedTime;
    public LinkType type;
    public LinkDirection direction;

    // Do NOT delete this, it's required for the serializer
    public LinkWithTopoInfo() {}

    public LinkWithTopoInfo(Link link,
                            LinkType type,
                            LinkDirection direction, LinkInfo info) {
        this.srcSwDpid = link.getSrc();
        this.srcPort = link.getSrcPort();
        this.dstSwDpid = link.getDst();
        this.dstPort = link.getDstPort();
        this.type = type;
        this.direction = direction;
        this.lastLldpReceivedTime = info.getUnicastValidTime() / 1000000;
        this.currentKnownDelay = info.getCurrentKnownDelay()  / 1000000;
        this.lastHpvReceivedTime = info.getLastHpvReceivedTime() / 1000000;
    }

    @Override
    public void serialize(LinkWithTopoInfo lwt, JsonGenerator jgen, SerializerProvider arg2)
            throws IOException, JsonProcessingException {
        // You ****MUST*** use lwt for the fields as it's actually a different object.
        jgen.writeStartObject();
        jgen.writeStringField("src-switch", HexString.toHexString(lwt.srcSwDpid));
        jgen.writeNumberField("src-port", lwt.srcPort);
        jgen.writeStringField("dst-switch", HexString.toHexString(lwt.dstSwDpid));
        jgen.writeNumberField("dst-port", lwt.dstPort);
        jgen.writeStringField("type", lwt.type.toString());
        jgen.writeStringField("direction", lwt.direction.toString());
        jgen.writeNumberField("last-lldp-received-time", lwt.lastLldpReceivedTime);
        jgen.writeNumberField("current-known-delay", lwt.currentKnownDelay);
        jgen.writeNumberField("last-hpv-received-time", lwt.lastHpvReceivedTime);
        jgen.writeEndObject();
        return;
    }

    @Override
    public Class<LinkWithTopoInfo> handledType() {
        return LinkWithTopoInfo.class;
    }
}