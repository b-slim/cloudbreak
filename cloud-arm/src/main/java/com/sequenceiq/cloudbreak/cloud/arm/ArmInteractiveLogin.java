package com.sequenceiq.cloudbreak.cloud.arm;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
import org.springframework.stereotype.Service;

import com.sequenceiq.cloudbreak.cloud.arm.context.ArmInteractiveLoginStatusCheckerContext;
import com.sequenceiq.cloudbreak.cloud.arm.task.ArmPollTaskFactory;
import com.sequenceiq.cloudbreak.cloud.context.AuthenticatedContext;
import com.sequenceiq.cloudbreak.cloud.model.ExtendedCloudCredential;
import com.sequenceiq.cloudbreak.cloud.scheduler.SyncPollingScheduler;
import com.sequenceiq.cloudbreak.cloud.task.PollTask;

/**
 * Created by perdos on 9/22/16.
 */
@Service
public class ArmInteractiveLogin {

    public static final String XPLAT_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

    @Inject
    private ArmPollTaskFactory armPollTaskFactory;

    @Inject
    private SyncPollingScheduler<Boolean> syncPollingScheduler;

    private static final Logger LOGGER = LoggerFactory.getLogger(ArmInteractiveLogin.class);

    public Map<String, String> login(AuthenticatedContext authenticatedContext, ExtendedCloudCredential extendedCloudCredential) {
        Client client = ClientBuilder.newClient();
        WebTarget resource = client.target("https://login.microsoftonline.com/common/oauth2");

        Form form = new Form();
        form.param("client_id", XPLAT_CLI_CLIENT_ID);
        form.param("resource", "https://management.core.windows.net/");
        form.param("mkt", "en-us");

        Invocation.Builder request = resource.path("devicecode?api-version=1.0").request();
        request.accept(MediaType.APPLICATION_JSON);
        Response response = request.post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            LOGGER.info("Success! " + response.getStatus());
            String jsonString = response.readEntity(String.class);
            try {
                JSONObject jsonObject = new JSONObject(jsonString);
                Map<String, String> parameters = new HashMap<>();
                parameters.put("user_code", jsonObject.getString("user_code"));
                parameters.put("verification_url", jsonObject.getString("verification_url"));
                int pollInterval = jsonObject.getInt("interval");
                int expiresIn = jsonObject.getInt("expires_in");
                String deviceCode = jsonObject.getString("device_code");

                ArmInteractiveLoginStatusCheckerContext armInteractiveLoginStatusCheckerContext = new ArmInteractiveLoginStatusCheckerContext(deviceCode, extendedCloudCredential);
                PollTask<Boolean> interactiveLoginStatusCheckerTask = armPollTaskFactory.interactiveLoginStatusCheckerTask(
                        authenticatedContext, armInteractiveLoginStatusCheckerContext);

                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.execute(() -> {
                    try {
                        syncPollingScheduler.schedule(interactiveLoginStatusCheckerTask, pollInterval, expiresIn / pollInterval, 1);
                    } catch (Exception e) {
                        LOGGER.error("Interactive login schedule failed", e);
                    }
                });

                return parameters;
            } catch (JSONException e) {
                throw new IllegalStateException(e);
            }
        } else {
            LOGGER.error("interactive login error, status: " + response.getStatus());
            throw new IllegalStateException("interactive login error");
        }
    }
}
