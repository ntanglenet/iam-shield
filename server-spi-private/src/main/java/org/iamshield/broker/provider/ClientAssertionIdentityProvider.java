package org.iamshield.broker.provider;

import org.iamshield.authentication.ClientAuthenticationFlowContext;

public interface ClientAssertionIdentityProvider {

    boolean verifyClientAssertion(ClientAuthenticationFlowContext context) throws Exception;

}
