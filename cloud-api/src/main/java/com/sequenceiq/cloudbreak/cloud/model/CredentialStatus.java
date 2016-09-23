package com.sequenceiq.cloudbreak.cloud.model;

import java.util.Map;

public enum CredentialStatus {

    CREATED(StatusGroup.PERMANENT),
    IN_PROGRESS(StatusGroup.PERMANENT),
    VERIFIED(StatusGroup.PERMANENT),
    DELETED(StatusGroup.PERMANENT),
    UPDATED(StatusGroup.PERMANENT),
    FAILED(StatusGroup.PERMANENT);

    private StatusGroup statusGroup;
    private Map<String, String> parameters;

    CredentialStatus(StatusGroup statusGroup) {
        this.statusGroup = statusGroup;
    }

    public StatusGroup getStatusGroup() {
        return statusGroup;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }
}
