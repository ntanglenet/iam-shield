package org.iamshield.authentication.authenticators;

import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.Authenticator;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

/**
 * Pass-thru atheneticator that just sets the context to attempted.
 */
public class AttemptedAuthenticator implements Authenticator {

    public static final AttemptedAuthenticator SINGLETON = new AttemptedAuthenticator();
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.attempted();

    }

    @Override
    public void action(AuthenticationFlowContext context) {
        throw new RuntimeException("Unreachable!");

    }

    @Override
    public boolean requiresUser() {
        return false;
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
