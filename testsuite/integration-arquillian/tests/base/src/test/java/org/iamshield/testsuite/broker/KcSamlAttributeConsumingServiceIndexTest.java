package org.iamshield.testsuite.broker;

import org.iamshield.broker.saml.SAMLIdentityProviderConfig;
import org.iamshield.dom.saml.v2.protocol.AuthnRequestType;
import org.iamshield.saml.common.util.DocumentUtil;
import org.iamshield.saml.processing.api.saml.v2.request.SAML2Request;
import org.iamshield.testsuite.saml.AbstractSamlTest;
import org.iamshield.testsuite.updaters.IdentityProviderAttributeUpdater;
import org.iamshield.testsuite.util.SamlClient;
import org.iamshield.testsuite.util.SamlClient.Binding;
import org.iamshield.testsuite.util.SamlClientBuilder;
import java.io.Closeable;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import static org.iamshield.testsuite.broker.BrokerTestTools.getConsumerRoot;

/**
 * Final class as it's not intended to be overriden.
 */
public final class KcSamlAttributeConsumingServiceIndexTest extends AbstractBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcSamlBrokerConfiguration.INSTANCE;
    }

    @Test
    public void testAttributeConsumingServiceIndexNotSet() throws Exception {
        // No Attribute Consuming Service Index set -> No attribute added to AuthnRequest
        try (Closeable idpUpdater = new IdentityProviderAttributeUpdater(identityProviderResource)
            .update())
        {
            // Build the login request document
            AuthnRequestType loginRep = SamlClient.createLoginRequestDocument(AbstractSamlTest.SAML_CLIENT_ID_SALES_POST + ".dot/ted", getConsumerRoot() + "/sales-post/saml", null);
            Document doc = SAML2Request.convert(loginRep);
            new SamlClientBuilder()
                .authnRequest(getConsumerSamlEndpoint(bc.consumerRealmName()), doc, Binding.POST)
                .build()   // Request to consumer IdP
                .login().idp(bc.getIDPAlias()).build()
                .processSamlResponse(Binding.POST)    // AuthnRequest to producer IdP
                  .targetAttributeSamlRequest()
                  .transformDocument((document) -> {
                    try
                    {
                        log.infof("Document: %s", DocumentUtil.asString(document));

                        // Find the AuthnRequest AttributeConsumingServiceIndex attribute
                        Node attrNode = document.getDocumentElement().getAttributes().getNamedItem("AttributeConsumingServiceIndex");
                        Assert.assertEquals("Unexpected AttributeConsumingServiceIndex attribute value", null, attrNode);
                    }
                    catch (Exception ex)
                    {
                        throw new RuntimeException(ex);
                    }
                  })
                  .build()
                .execute();
        }
    }

    @Test
    public void testAttributeConsumingServiceIndexSet() throws Exception {
        // Attribute Consuming Service Index set -> Attribute added to AuthnRequest
        try (Closeable idpUpdater = new IdentityProviderAttributeUpdater(identityProviderResource)
            .setAttribute(SAMLIdentityProviderConfig.ATTRIBUTE_CONSUMING_SERVICE_INDEX, "15")
            .update())
        {
            // Build the login request document
            AuthnRequestType loginRep = SamlClient.createLoginRequestDocument(AbstractSamlTest.SAML_CLIENT_ID_SALES_POST + ".dot/ted", getConsumerRoot() + "/sales-post/saml", null);
            Document doc = SAML2Request.convert(loginRep);
            new SamlClientBuilder()
                .authnRequest(getConsumerSamlEndpoint(bc.consumerRealmName()), doc, Binding.POST)
                .build()   // Request to consumer IdP
                .login().idp(bc.getIDPAlias()).build()
                .processSamlResponse(Binding.POST)    // AuthnRequest to producer IdP
                  .targetAttributeSamlRequest()
                  .transformDocument((document) -> {
                    try
                    {
                        log.infof("Document: %s", DocumentUtil.asString(document));

                        // Find the AuthnRequest AttributeConsumingServiceIndex attribute
                        String attrValue = document.getDocumentElement().getAttributes().getNamedItem("AttributeConsumingServiceIndex").getNodeValue();
                        Assert.assertEquals("Unexpected AttributeConsumingServiceIndex attribute value", "15", attrValue);
                    }
                    catch (Exception ex)
                    {
                        throw new RuntimeException(ex);
                    }
                  })
                  .build()
                .execute();
        }
    }
}
