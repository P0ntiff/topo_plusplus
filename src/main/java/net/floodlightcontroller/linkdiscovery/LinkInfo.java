/**
*    Copyright 2011, Big Switch Networks, Inc.*    Originally created by David Erickson, Stanford University
**    Licensed under the Apache License, Version 2.0 (the "License"); you may
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

package net.floodlightcontroller.linkdiscovery;

import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LinkType;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class LinkInfo {

    public LinkInfo(Long firstSeenTime,
                    Long lastLldpReceivedTime,
                    Long lastBddpReceivedTime) {
        super();
        this.firstSeenTime = firstSeenTime;
        this.lastLldpReceivedTime = lastLldpReceivedTime;
        this.lastBddpReceivedTime = lastBddpReceivedTime;
    }

    public LinkInfo(Long firstSeenTime,
                    Long lastLldpReceivedTime,
                    Long lastBddpReceivedTime,
                    Long currentKnownDelay) {
        super();
        this.firstSeenTime = firstSeenTime;
        this.lastLldpReceivedTime = lastLldpReceivedTime;
        this.lastBddpReceivedTime = lastBddpReceivedTime;
        this.currentKnownDelay = currentKnownDelay;
    }

    public LinkInfo(Long firstSeenTime,
                    Long lastLldpReceivedTime,
                    Long lastBddpReceivedTime,
                    Long currentKnownDelay,
                    Long lastHpvReceivedTime) {
        super();
        this.firstSeenTime = firstSeenTime;
        this.lastLldpReceivedTime = lastLldpReceivedTime;
        this.lastBddpReceivedTime = lastBddpReceivedTime;
        this.currentKnownDelay = currentKnownDelay;
        this.lastHpvReceivedTime = lastHpvReceivedTime;
    }

    /*
     * Do not use this constructor. Used primarily for JSON
     * Serialization/Deserialization
     */
    public LinkInfo() {
        this.firstSeenTime = null;
        this.lastLldpReceivedTime = null;
        this.lastBddpReceivedTime = null;
        this.currentKnownDelay = null;
        this.lastHpvReceivedTime = null;
        this.hpvVerifiedStatus = false;
        this.statsVerifiedStatus = false;
    }

    public LinkInfo(LinkInfo fromLinkInfo) {
        this.firstSeenTime = fromLinkInfo.getFirstSeenTime();
        this.lastLldpReceivedTime = fromLinkInfo.getUnicastValidTime();
        this.lastBddpReceivedTime = fromLinkInfo.getMulticastValidTime();
        this.currentKnownDelay = fromLinkInfo.getCurrentKnownDelay();
        this.lastHpvReceivedTime = fromLinkInfo.getLastHpvReceivedTime();
        this.hpvVerifiedStatus = fromLinkInfo.getHpvVerifiedStatus();
        this.statsVerifiedStatus = fromLinkInfo.getStatsVerifiedStatus();
    }

    protected Long firstSeenTime;
    protected Long lastLldpReceivedTime; /* Standard LLLDP received time */
    protected Long lastBddpReceivedTime; /* Modified LLDP received time  */
    protected Long currentKnownDelay = 0L;   /* TopoGuard+ link delay information */
    protected Long lastHpvReceivedTime = 0L;    /* TopoGuard++ HPV information */
    protected boolean hpvVerifiedStatus = false;   /* TopoGuard++ HPV status */
    protected boolean statsVerifiedStatus = false;   /* TopoGuard++ Statistics Verification status */

    /** The port states stored here are topology's last knowledge of
     * the state of the port. This mostly mirrors the state
     * maintained in the port list in IOFSwitch (i.e. the one returned
     * from getPort), except that during a port status message the
     * IOFSwitch port state will already have been updated with the
     * new port state, so topology needs to keep its own copy so that
     * it can determine if the port state has changed and therefore
     * requires the new state to be written to storage.
     */

    public Long getFirstSeenTime() {
        return firstSeenTime;
    }

    public void setFirstSeenTime(Long firstSeenTime) {
        this.firstSeenTime = firstSeenTime;
    }

    public Long getUnicastValidTime() {
        return lastLldpReceivedTime;
    }

    public void setUnicastValidTime(Long unicastValidTime) {
        this.lastLldpReceivedTime = unicastValidTime;
    }

    public Long getMulticastValidTime() {
        return lastBddpReceivedTime;
    }

    public void setMulticastValidTime(Long multicastValidTime) {
        this.lastBddpReceivedTime = multicastValidTime;
    }

    public Long getCurrentKnownDelay() {
        return currentKnownDelay;
    }

    public void setCurrentKnownDelay(Long currentKnownDelay) {
        this.currentKnownDelay = currentKnownDelay;
    }

    public Long getLastHpvReceivedTime() {
        return lastHpvReceivedTime;
    }

    public void setLastHpvReceivedTime(Long lastHpvReceivedTime) {
        this.lastHpvReceivedTime = lastHpvReceivedTime;
    }

    public boolean getHpvVerifiedStatus() {
        return hpvVerifiedStatus;
    }

    public void setHpvVerifiedStatus(boolean hpvVerifiedStatus) {
        this.hpvVerifiedStatus = hpvVerifiedStatus;
    }

    public boolean getStatsVerifiedStatus() {
        return statsVerifiedStatus;
    }

    public void setStatsVerifiedStatus(boolean statsVerifiedStatus) {
        this.statsVerifiedStatus = statsVerifiedStatus;
    }

    @JsonIgnore
    public LinkType getLinkType() {
        if (lastLldpReceivedTime != null) {
            return LinkType.DIRECT_LINK;
        } else if (lastBddpReceivedTime != null) {
            return LinkType.MULTIHOP_LINK;
        }
        return LinkType.INVALID_LINK;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 5557;
        int result = 1;
        result = prime * result + ((firstSeenTime == null) ? 0 : firstSeenTime.hashCode());
        result = prime * result + ((lastLldpReceivedTime == null) ? 0 : lastLldpReceivedTime.hashCode());
        result = prime * result + ((lastBddpReceivedTime == null) ? 0 : lastBddpReceivedTime.hashCode());
        result = prime * result + ((currentKnownDelay == null) ? 0 : currentKnownDelay.hashCode());
        result = prime * result + ((lastHpvReceivedTime == null) ? 0 : lastHpvReceivedTime.hashCode());
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof LinkInfo))
            return false;
        LinkInfo other = (LinkInfo) obj;

        if (firstSeenTime == null) {
            if (other.firstSeenTime != null)
                return false;
        } else if (!firstSeenTime.equals(other.firstSeenTime))
            return false;

        if (lastLldpReceivedTime == null) {
            if (other.lastLldpReceivedTime != null)
                return false;
        } else if (!lastLldpReceivedTime.equals(other.lastLldpReceivedTime))
            return false;

        if (lastBddpReceivedTime == null) {
            if (other.lastBddpReceivedTime != null)
                return false;
        } else if (!lastBddpReceivedTime.equals(other.lastBddpReceivedTime))
            return false;

        if (currentKnownDelay == null) {
            if (other.currentKnownDelay != null)
                return false;
        } else if (!currentKnownDelay.equals(other.currentKnownDelay))
            return false;

        if (lastHpvReceivedTime == null) {
            if (other.lastHpvReceivedTime != null)
                return false;
        } else if (!lastHpvReceivedTime.equals(other.lastHpvReceivedTime))
            return false;

        if (other.hpvVerifiedStatus != hpvVerifiedStatus) {
            return false;
        }

        if (other.statsVerifiedStatus != statsVerifiedStatus) {
            return false;
        }

        return true;
    }


    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "LinkInfo [unicastValidTime=" + ((lastLldpReceivedTime == null) ? "null" : lastLldpReceivedTime)
                + ", multicastValidTime=" + ((lastBddpReceivedTime == null) ? "null" : lastBddpReceivedTime)
                + ", currentKnownDelay=" + ((currentKnownDelay == null) ? "null" : currentKnownDelay)
                + ", lastHpvReceivedTime=" + ((lastHpvReceivedTime == null) ? "null" : lastHpvReceivedTime)
                + ", hpvVerifiedStatus=" + hpvVerifiedStatus + "]"
                + ", statsVerifiedStatus=" + statsVerifiedStatus + "]";

    }
}
