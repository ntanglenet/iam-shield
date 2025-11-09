package org.iamshield.testsuite.saml;

import org.iamshield.protocol.saml.SamlConfigAttributes;
import org.iamshield.protocol.saml.SamlProtocol;
import org.junit.Test;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.saml.common.exceptions.ConfigurationException;
import org.iamshield.saml.common.exceptions.ParsingException;
import org.iamshield.saml.common.exceptions.ProcessingException;
import org.iamshield.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.iamshield.testsuite.util.ClientBuilder;
import org.iamshield.testsuite.utils.io.IOUtil;

import org.iamshield.testsuite.util.SamlClient.Binding;
import org.iamshield.testsuite.util.SamlClientBuilder;
import java.util.List;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author mhajas
 */
public class SamlConsentTest extends AbstractSamlTest {

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(IOUtil.loadRealm("/adapter-test/keycloak-saml/testsaml.json"));
    }

    @Test
    public void rejectedConsentResponseTest() throws ParsingException, ConfigurationException, ProcessingException {
        ClientRepresentation client = adminClient.realm(REALM_NAME)
                .clients()
                .findByClientId(SAML_CLIENT_ID_SALES_POST)
                .get(0);

        adminClient.realm(REALM_NAME)
                .clients()
                .get(client.getId())
                .update(ClientBuilder.edit(client)
                        .consentRequired(true)
                        .attribute(SamlProtocol.SAML_IDP_INITIATED_SSO_URL_NAME, "sales-post")
                        .attribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, SAML_ASSERTION_CONSUMER_URL_SALES_POST + "saml")
                        .attribute(SamlConfigAttributes.SAML_SERVER_SIGNATURE, "true")
                        .build());

        log.debug("Log in using idp initiated login");
        SAMLDocumentHolder documentHolder = new SamlClientBuilder()
          .authnRequest(getAuthServerSamlEndpoint(REALM_NAME), SAML_CLIENT_ID_SALES_POST, SAML_ASSERTION_CONSUMER_URL_SALES_POST, Binding.POST).build()
          .login().user(bburkeUser).build()
          .consentRequired().approveConsent(false).build()
          .getSamlResponse(Binding.POST);

        final String samlDocumentString = IOUtil.documentToString(documentHolder.getSamlDocument());
        assertThat(samlDocumentString, containsString("<dsig:Signature")); // KEYCLOAK-4262
        assertThat(samlDocumentString, not(containsString("<samlp:LogoutResponse"))); // KEYCLOAK-4261
        assertThat(samlDocumentString, containsString("<samlp:Response")); // KEYCLOAK-4261
        assertThat(samlDocumentString, containsString("<samlp:Status")); // KEYCLOAK-4181
        assertThat(samlDocumentString, containsString("<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:RequestDenied\"")); // KEYCLOAK-4181
    }
}
