package com.sequenceiq.cloudbreak.service.blueprint;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.inject.Inject;

import org.springframework.stereotype.Service;

import com.sequenceiq.cloudbreak.domain.Cluster;
import com.sequenceiq.cloudbreak.domain.HostGroup;
import com.sequenceiq.cloudbreak.domain.InstanceMetaData;
import com.sequenceiq.cloudbreak.service.cluster.flow.blueprint.BlueprintProcessor;
import com.sequenceiq.cloudbreak.service.hostgroup.HostGroupService;

@Service
public class ComponentLocatorService {

    @Inject
    private BlueprintProcessor blueprintProcessor;

    @Inject
    private HostGroupService hostGroupService;

    public Map<String, List<String>> getComponentLocation(Cluster cluster, Set<String> componentNames) {
        Map<String, List<String>> result = new HashMap<>();
        for (HostGroup hg : hostGroupService.getByCluster(cluster.getId())) {
            Set<String> hgComponents = blueprintProcessor.getComponentsInHostGroup(cluster.getBlueprint().getBlueprintText(), hg.getName());
            hgComponents.retainAll(componentNames);

            List<String> fqdn = hg.getConstraint().getInstanceGroup().getInstanceMetaData().stream()
                    .map(InstanceMetaData::getDiscoveryFQDN).collect(Collectors.toList());
            for (String service : hgComponents) {
                List<String> storedAddresses = result.get(service);
                if (storedAddresses == null) {
                    result.put(service, fqdn);
                } else {
                    storedAddresses.addAll(fqdn);
                }
            }
        }
        return result;
    }
}
