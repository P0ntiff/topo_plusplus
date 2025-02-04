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

import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LinkDirection;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LinkType;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.linkdiscovery.web.LinkWithType;
import net.floodlightcontroller.routing.Link;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class LinksVerificationResource extends ServerResource {

    @Get("json")
    public Set<LinkWithTopoInfo> retrieve() {
        ILinkDiscoveryService ld = (ILinkDiscoveryService)getContext().getAttributes().
                get(ILinkDiscoveryService.class.getCanonicalName());
        Map<Link, LinkInfo> links = new HashMap<Link, LinkInfo>();
        Set<LinkWithTopoInfo> returnLinkSet = new HashSet<LinkWithTopoInfo>();

        if (ld != null) {
            links.putAll(ld.getLinks());
            for (Link link: links.keySet()) {
                LinkInfo info = links.get(link);
                LinkType type = ld.getLinkType(link, info);
                if (type == LinkType.DIRECT_LINK || type == LinkType.TUNNEL) {
                    LinkWithTopoInfo lwt;

                    long src = link.getSrc();
                    long dst = link.getDst();
                    short srcPort = link.getSrcPort();
                    short dstPort = link.getDstPort();
                    Link otherLink = new Link(dst, dstPort, src, srcPort);
                    LinkInfo otherInfo = links.get(otherLink);
                    LinkType otherType = null;
                    if (otherInfo != null)
                        otherType = ld.getLinkType(otherLink, otherInfo);
                    if (otherType == LinkType.DIRECT_LINK ||
                            otherType == LinkType.TUNNEL) {
                        // This is a bi-direcitonal link.
                        // It is sufficient to add only one side of it.
                        if ((src < dst) || (src == dst && srcPort < dstPort)) {
                            lwt = new LinkWithTopoInfo(link,
                                    type,
                                    LinkDirection.BIDIRECTIONAL, info);
                            returnLinkSet.add(lwt);
                        }
                    } else {
                        // This is a unidirectional link.
                        lwt = new LinkWithTopoInfo(link,
                                type,
                                LinkDirection.UNIDIRECTIONAL, info);
                        returnLinkSet.add(lwt);

                    }
                }
            }
        }
        return returnLinkSet;
    }
}
