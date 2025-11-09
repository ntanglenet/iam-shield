package org.iamshield.protocol.oid4vc.issuance.credentialbuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.iamshield.common.Profile;
import org.iamshield.common.Profile.Feature;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.common.crypto.CryptoProvider;
import org.iamshield.common.profile.CommaSeparatedListProfileConfigResolver;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.services.resteasy.ResteasyIAMShieldSession;
import org.iamshield.services.resteasy.ResteasyIAMShieldSessionFactory;

public class CredentialBuilderFactoryTest {

    private static IAMShieldSession session;

    @BeforeClass
    public static void beforeClass() {
        Profile.configure(new CommaSeparatedListProfileConfigResolver(Feature.OID4VC_VCI.getVersionedKey(), ""));
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        ResteasyIAMShieldSessionFactory factory = new ResteasyIAMShieldSessionFactory();
        factory.init();
        session = new ResteasyIAMShieldSession(factory);
    }

    @Test
    public void testVerifyNonNullConfigProperties() {
        List<CredentialBuilderFactory> credentialBuilderFactories = session
            .getIAMShieldSessionFactory()
            .getProviderFactoriesStream(CredentialBuilder.class)
            .filter(CredentialBuilderFactory.class::isInstance)
            .map(CredentialBuilderFactory.class::cast)
            .toList();

        assertThat(credentialBuilderFactories, is(not(empty())));

        for (CredentialBuilderFactory credentialBuilderFactory : credentialBuilderFactories) {
            assertThat(credentialBuilderFactory.getConfigProperties(), notNullValue());
        }
    }
}
