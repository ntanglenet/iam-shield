package org.iamshield.testsuite.authentication;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.AuthenticationFlowError;
import org.iamshield.authentication.Authenticator;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class SetUserAttributeAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Retrieve configuration
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String attrName = config.get(SetUserAttributeAuthenticatorFactory.CONF_ATTR_NAME);
        String attrValue = config.get(SetUserAttributeAuthenticatorFactory.CONF_ATTR_VALUE);

        UserModel user = context.getUser();
        List<String> attrValues = user.getAttributeStream(attrName).collect(Collectors.toList());
        if (attrValues.isEmpty()) {
            user.setSingleAttribute(attrName, attrValue);
        }
        else {
            if (!attrValues.contains(attrValue)) {
                attrValues.add(attrValue);
            }
            user.setAttribute(attrName, attrValues);
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(IAMShieldSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}
