package com.sequenceiq.cloudbreak.cloud.arm.task;

import static com.sequenceiq.cloudbreak.cloud.arm.ArmInteractiveLogin.XPLAT_CLI_CLIENT_ID;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.sequenceiq.cloudbreak.cloud.arm.context.ArmInteractiveLoginStatusCheckerContext;
import com.sequenceiq.cloudbreak.cloud.arm.view.ArmCredentialView;
import com.sequenceiq.cloudbreak.cloud.context.AuthenticatedContext;
import com.sequenceiq.cloudbreak.cloud.event.credential.InteractiveCredentialCreationRequest;
import com.sequenceiq.cloudbreak.cloud.model.CloudCredential;
import com.sequenceiq.cloudbreak.cloud.model.ExtendedCloudCredential;
import com.sequenceiq.cloudbreak.cloud.task.PollBooleanStateTask;

import reactor.bus.Event;
import reactor.bus.EventBus;

/**
 * Created by perdos on 9/22/16.
 */
@Component(ArmInteractiveLoginStatusCheckerTask.NAME)
@Scope(value = "prototype")
public class ArmInteractiveLoginStatusCheckerTask extends PollBooleanStateTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(ArmInteractiveLoginStatusCheckerTask.class);
    private final ArmInteractiveLoginStatusCheckerContext armInteractiveLoginStatusCheckerContext;
    private static final String OWNER_ROLE = "Owner";
    private static final String PASSWORD = "cloudbreak";
    public static final String NAME = "armInteractiveLoginStatusCheckerTask";

    @Inject
    private EventBus eventBus;

    public ArmInteractiveLoginStatusCheckerTask(AuthenticatedContext authenticatedContext,
            ArmInteractiveLoginStatusCheckerContext armInteractiveLoginStatusCheckerContext) {
        super(authenticatedContext, false);
        this.armInteractiveLoginStatusCheckerContext = armInteractiveLoginStatusCheckerContext;
    }

    @Override
    public Boolean call() {
        Form pollingForm = new Form();
        pollingForm.param("grant_type", "device_code");
        pollingForm.param("client_id", XPLAT_CLI_CLIENT_ID);
        pollingForm.param("resource", "https://management.core.windows.net/");
        pollingForm.param("code", armInteractiveLoginStatusCheckerContext.getDeviceCode());

        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target("https://login.microsoftonline.com/common/oauth2");

        Invocation.Builder request = resource.path("token").queryParam("api-version", "1.0").request();
        request.accept(MediaType.APPLICATION_JSON);
        Response response = request.post(Entity.entity(pollingForm, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            String tokenResponseString = response.readEntity(String.class);
            try {
                JSONObject tokenResponseObject = new JSONObject(tokenResponseString);

                CloudCredential cloudCredential = getAuthenticatedContext().getCloudCredential();
                ArmCredentialView armCredentialView = new ArmCredentialView(cloudCredential);
                String accessToken = tokenResponseObject.getString("access_token");

                String appId = createApplication(accessToken, armCredentialView);
                String principalObjectId = createServicePrincipal(accessToken, appId, armCredentialView);
                String roleDefinitionId = getOwnerRoleNameRoleIdPair(accessToken, armCredentialView);
                assignRole(roleDefinitionId, principalObjectId, accessToken, armCredentialView);

                ExtendedCloudCredential extendedCloudCredential = armInteractiveLoginStatusCheckerContext.getExtendedCloudCredential();

                extendedCloudCredential.putParameter("accessKey", appId);
                extendedCloudCredential.putParameter("secretKey", PASSWORD);

                InteractiveCredentialCreationRequest credentialCreationRequest =
                        new InteractiveCredentialCreationRequest(getAuthenticatedContext().getCloudContext(), cloudCredential, extendedCloudCredential);
                LOGGER.info("Triggering event: {}", credentialCreationRequest);
                eventBus.notify(credentialCreationRequest.selector(), Event.wrap(credentialCreationRequest));
            } catch (JSONException e) {
                throw new IllegalStateException(e);
            }
            return true;
        } else {
            return false;
        }
    }

    private String createApplication(String accessToken, ArmCredentialView armCredentialView) {
        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target("https://graph.windows.net/" + armCredentialView.getTenantId());

        Invocation.Builder request = resource.path("/applications").queryParam("api-version", "1.42-previewInternal").request();
        request.accept(MediaType.APPLICATION_JSON);

        long timeStamp = new Date().getTime();

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("availableToOtherTenants", false);
        jsonObject.addProperty("displayName", "hwx-cloud-" + timeStamp);
        jsonObject.addProperty("homepage", "http://hwx-cloud-" + timeStamp);

        JsonArray identifierUris = new JsonArray();
        identifierUris.add(new JsonPrimitive("http://hwx-cloud-" + timeStamp));
        jsonObject.add("identifierUris", identifierUris);

        JsonArray passwordCredentials = new JsonArray();
        JsonObject password = new JsonObject();
        password.addProperty("keyId", UUID.randomUUID().toString());
        password.addProperty("value", "cloudbreak");
        password.addProperty("startDate", LocalDateTime.now().minusDays(1).toString());
        password.addProperty("endDate", LocalDateTime.now().plusYears(3).toString());
        passwordCredentials.add(password);

        jsonObject.add("passwordCredentials", passwordCredentials);

        request.header("Authorization", "Bearer " + accessToken);
        Response response = request.post(Entity.entity(jsonObject.toString(), MediaType.APPLICATION_JSON));

        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            String application = response.readEntity(String.class);

            try {
                JSONObject applicationJson = new JSONObject(application);
                String appId = applicationJson.getString("appId");
                LOGGER.info("Application created with appId: " + appId);
                return appId;
            } catch (JSONException e) {
                throw new IllegalStateException(e);
            }
        } else {
            throw new IllegalStateException("Application error - status code: " + response.getStatus() +
                    " - error message: " + response.readEntity(String.class));
        }

    }

    private String createServicePrincipal(String accessToken, String appId, ArmCredentialView armCredentialView) {
        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target("https://graph.windows.net/" + armCredentialView.getTenantId());

        Invocation.Builder request = resource.path("servicePrincipals").queryParam("api-version", "1.42-previewInternal").request();
        request.accept(MediaType.APPLICATION_JSON);

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("appId", appId);
        jsonObject.addProperty("accountEnabled", true);

        request.header("Authorization", "Bearer " + accessToken);
        Response response = request.post(Entity.entity(jsonObject.toString(), MediaType.APPLICATION_JSON));

        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            String principal = response.readEntity(String.class);

            try {
                JSONObject principalJson = new JSONObject(principal);
                String objectId = principalJson.getString("objectId");
                LOGGER.info("Service principal created with objectId: " + objectId);
                return objectId;
            } catch (JSONException e) {
                throw new IllegalStateException(e);
            }
        } else {
            throw new IllegalStateException("Service principal creation error - status code: " + response.getStatus() +
                    " - error message: " + response.readEntity(String.class));
        }
    }

    private String getOwnerRoleNameRoleIdPair(String accessToken, ArmCredentialView armCredentialView) {
        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target("https://management.azure.com");

        Invocation.Builder request = resource.path("subscriptions/" + armCredentialView.getSubscriptionId() +
                "/providers/Microsoft.Authorization/roleDefinitions")
                .queryParam("$filter", "roleName%20eq%20'" + OWNER_ROLE + "'")
                .queryParam("api-version", "2015-07-01")
                .request();
        request.accept(MediaType.APPLICATION_JSON);

        request.header("Authorization", "Bearer " + accessToken);
        Response response = request.get();

        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            String roles = response.readEntity(String.class);

            try {
                JSONObject rolesJson = new JSONObject(roles);

                String roleDefinitionId = rolesJson.getJSONArray("value").getJSONObject(0).getString("id");
                LOGGER.info("Role definition - roleId: " + roleDefinitionId);

                return roleDefinitionId;
            } catch (JSONException e) {
                throw new IllegalStateException(e);
            }
        } else {
            throw new IllegalStateException("get 'Owner' role name and id request error - status code: " + response.getStatus() +
                    " - error message: " + response.readEntity(String.class));
        }

    }

    private void assignRole(String roleDefinitionId, String principalObjectId, String accessToken, ArmCredentialView armCredentialView) {
        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target("https://management.azure.com");

        Invocation.Builder request = resource.path("subscriptions/" + armCredentialView.getSubscriptionId() +
                "/providers/Microsoft.Authorization/roleAssignments/" + UUID.randomUUID().toString()).queryParam("api-version", "2015-07-01").request();
        request.accept(MediaType.APPLICATION_JSON);

        request.header("Authorization", "Bearer " + accessToken);

        JsonObject properties = new JsonObject();
        properties.addProperty("roleDefinitionId", roleDefinitionId);
        properties.addProperty("principalId", principalObjectId);

        JsonObject jsonObject = new JsonObject();
        jsonObject.add("properties", properties);

        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        Response response = request.put(Entity.entity(jsonObject.toString(), MediaType.APPLICATION_JSON));

        if (response.getStatusInfo().getFamily() != Response.Status.Family.SUCCESSFUL) {
            throw new IllegalStateException("Assign role request error - status code: " + response.getStatus() +
                    " - error message: " + response.readEntity(String.class));
        } else {
            LOGGER.info("Role assigned successfully");
        }
    }

}
