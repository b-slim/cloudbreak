package com.sequenceiq.cloudbreak.reactor;

import javax.inject.Inject;

import org.springframework.stereotype.Component;

import com.sequenceiq.cloudbreak.cloud.event.credential.InteractiveCredentialCreationRequest;
import com.sequenceiq.cloudbreak.cloud.model.ExtendedCloudCredential;
import com.sequenceiq.cloudbreak.controller.AuthenticatedUserService;
import com.sequenceiq.cloudbreak.converter.spi.ExtendedCloudCredentialToCredentialConverter;
import com.sequenceiq.cloudbreak.domain.Credential;
import com.sequenceiq.cloudbreak.service.credential.CredentialService;

import reactor.bus.Event;

/**
 * Created by perdos on 9/23/16.
 */
@Component
public class InteractiveCredentialCreationHandler implements ClusterEventHandler<InteractiveCredentialCreationRequest> {

    @Inject
    private CredentialService credentialService;

    @Inject
    private ExtendedCloudCredentialToCredentialConverter extendedCloudCredentialToCredentialConverter;

    @Inject
    AuthenticatedUserService authenticatedUserService;

    @Override
    public Class<InteractiveCredentialCreationRequest> type() {
        return InteractiveCredentialCreationRequest.class;
    }

    @Override
    public void accept(Event<InteractiveCredentialCreationRequest> interactiveCredentialCreationRequestEvent) {
        InteractiveCredentialCreationRequest interactiveCredentialCreationRequest = interactiveCredentialCreationRequestEvent.getData();

        ExtendedCloudCredential extendedCloudCredential = interactiveCredentialCreationRequest.getExtendedCloudCredential();
        Credential credential = extendedCloudCredentialToCredentialConverter.convert(extendedCloudCredential);
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        credentialService.create(extendedCloudCredential.getOwner(), extendedCloudCredential.getAccount(), credential);
    }
}
