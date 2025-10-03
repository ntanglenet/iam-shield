package org.iamshield.testsuite.broker;

import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;

public interface NestedBrokerConfiguration extends BrokerConfiguration {

    RealmRepresentation createSubConsumerRealm();

    String subConsumerRealmName();

    IdentityProviderRepresentation setUpConsumerIdentityProvider();

    String getSubConsumerIDPDisplayName();
}
