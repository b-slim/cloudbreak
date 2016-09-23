package com.sequenceiq.cloudbreak.cloud.event.credential;

import java.util.Map;

import com.sequenceiq.cloudbreak.cloud.event.CloudPlatformRequest;
import com.sequenceiq.cloudbreak.cloud.event.CloudPlatformResult;

public class InteractiveCredentialCreationResult extends CloudPlatformResult<CloudPlatformRequest> {

    private Map<String, String> parameters;

    public InteractiveCredentialCreationResult(CloudPlatformRequest<InteractiveCredentialCreationResult> request, Map<String, String> parameters) {
        super(request);
        this.parameters = parameters;
    }

    public InteractiveCredentialCreationResult(String statusReason, Exception errorDetails, CloudPlatformRequest<InteractiveCredentialCreationResult> request) {
        super(statusReason, errorDetails, request);
    }

    public Map<String, String> getParameters() {
        return parameters;
    }
}
