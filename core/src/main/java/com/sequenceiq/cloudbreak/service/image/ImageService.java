package com.sequenceiq.cloudbreak.service.image;

import static com.sequenceiq.cloudbreak.cloud.model.Platform.platform;

import java.io.IOException;
import java.util.Map;

import javax.inject.Inject;
import javax.transaction.Transactional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sequenceiq.cloudbreak.api.model.InstanceGroupType;
import com.sequenceiq.cloudbreak.cloud.PlatformParameters;
import com.sequenceiq.cloudbreak.cloud.model.HDPInfo;
import com.sequenceiq.cloudbreak.cloud.model.Image;
import com.sequenceiq.cloudbreak.cloud.model.Platform;
import com.sequenceiq.cloudbreak.common.type.ComponentType;
import com.sequenceiq.cloudbreak.core.CloudbreakImageNotFoundException;
import com.sequenceiq.cloudbreak.core.CloudbreakSecuritySetupException;
import com.sequenceiq.cloudbreak.domain.Component;
import com.sequenceiq.cloudbreak.domain.Stack;
import com.sequenceiq.cloudbreak.domain.json.Json;
import com.sequenceiq.cloudbreak.repository.ComponentRepository;
import com.sequenceiq.cloudbreak.service.CloudbreakServiceException;
import com.sequenceiq.cloudbreak.service.TlsSecurityService;

@Service
@Transactional
public class ImageService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ImageService.class);

    private static final String IMAGE_NAME = "IMAGE";

    @Inject
    private ImageNameUtil imageNameUtil;

    @Inject
    private HdpInfoSearchService hdpInfoSearchService;

    @Inject
    private UserDataBuilder userDataBuilder;

    @Inject
    private ComponentRepository componentRepository;

    @Inject
    private TlsSecurityService tlsSecurityService;

    public Image getImage(Long stackId) throws CloudbreakImageNotFoundException {
        try {
            Component component = componentRepository.findComponentByStackIdComponentTypeName(stackId, ComponentType.IMAGE, IMAGE_NAME);
            if (component == null) {
                throw new CloudbreakImageNotFoundException(String.format("Image not found: stackId: %d, componentType: %s, name: %s",
                        stackId, ComponentType.IMAGE.name(), IMAGE_NAME));
            }
            LOGGER.debug("Image found! stackId: {}, component: {}", stackId, component);
            return component.getAttributes().get(Image.class);
        } catch (IOException e) {
            throw new CloudbreakServiceException("Failed to read image", e);
        }
    }

    @Transactional(Transactional.TxType.NEVER)
    public void create(Stack stack, PlatformParameters params, String ambariVersion, String hdpVersion) {
        try {
            Platform platform = platform(stack.cloudPlatform());
            String platformString = platform(stack.cloudPlatform()).value().toLowerCase();
            String imageName = imageNameUtil.determineImageName(platformString, stack.getRegion(), ambariVersion, hdpVersion);
            String tmpSshKey = tlsSecurityService.readPublicSshKey(stack.getId());
            String sshUser = stack.getCredential().getLoginUserName();
            String publicSssKey = stack.getCredential().getPublicKey();
            Map<InstanceGroupType, String> userData = userDataBuilder.buildUserData(platform, publicSssKey, tmpSshKey, sshUser, params,
                    stack.getRelocateDocker() == null ? false : stack.getRelocateDocker());
            HDPInfo hdpInfo = hdpInfoSearchService.searchHDPInfo(ambariVersion, hdpVersion);
            if (hdpInfo != null) {
                String specificImage = imageNameUtil.determineImageName(hdpInfo, platformString, stack.getRegion());
                if (specificImage == null) {
                    LOGGER.warn("Cannot find image in the catalog, fallback to default image, ambari: {}, hdp: {}", ambariVersion, hdpVersion);
                    hdpInfo = null;
                } else {
                    LOGGER.info("Determined image from catalog: {}", specificImage);
                    imageName = specificImage;
                }
            }
            Image image;
            if (hdpInfo == null) {
                image = new Image(imageName, userData, null, null);
            } else {
                image = new Image(imageName, userData, hdpInfo.getRepo(), hdpInfo.getVersion());
            }
            Component component = new Component(ComponentType.IMAGE, IMAGE_NAME, new Json(image), stack);
            componentRepository.save(component);
            LOGGER.debug("Image saved: stackId: {}, component: {}", stack.getId(), component);
        } catch (JsonProcessingException e) {
            throw new CloudbreakServiceException("Failed to create json", e);
        } catch (CloudbreakSecuritySetupException e) {
            throw new CloudbreakServiceException("Failed to read temporary ssh credentials", e);
        }
    }


}
