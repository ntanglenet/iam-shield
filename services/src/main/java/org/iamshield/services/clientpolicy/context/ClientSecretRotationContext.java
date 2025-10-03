package org.iamshield.services.clientpolicy.context;

import org.iamshield.models.ClientModel;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.services.clientpolicy.ClientPolicyEvent;
import org.iamshield.utils.StringUtil;

public class ClientSecretRotationContext extends AdminClientUpdateContext {

    private final String currentSecret;

    public ClientSecretRotationContext(ClientRepresentation proposedClientRepresentation,
                                       ClientModel targetClient, String currentSecret) {
        super(proposedClientRepresentation, targetClient, null);
        this.currentSecret = currentSecret;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.UPDATED;
    }

    public String getCurrentSecret() {
        return currentSecret;
    }

    public boolean isForceRotation() {
        return StringUtil.isNotBlank(currentSecret);
    }
}
