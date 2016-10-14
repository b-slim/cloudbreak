package com.sequenceiq.cloudbreak.cloud.openstack.view;

import static org.apache.commons.lang3.StringUtils.isNoneEmpty;

import com.sequenceiq.cloudbreak.cloud.model.Network;
import com.sequenceiq.cloudbreak.cloud.openstack.common.OpenStackConstants;

public class NeutronNetworkView {

    private Network network;

    public NeutronNetworkView(Network network) {
        this.network = network;
    }

    public String getSubnetCIDR() {
        return network.getSubnet().getCidr();
    }

    public boolean assignFloatingIp() {
        return isNoneEmpty(getPublicNetId());
    }

    public String getPublicNetId() {
        return network.getStringParameter(OpenStackConstants.PUBLIC_NET_ID);
    }

}


