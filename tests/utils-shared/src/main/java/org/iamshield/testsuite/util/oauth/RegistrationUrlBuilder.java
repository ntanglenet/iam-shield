package org.iamshield.testsuite.util.oauth;

public class RegistrationUrlBuilder extends LoginUrlBuilder {

    public RegistrationUrlBuilder(AbstractOAuthClient<?> client) {
        super(client);
    }

    @Override
    public String getEndpoint() {
        return client.getEndpoints().getRegistration();
    }

}
