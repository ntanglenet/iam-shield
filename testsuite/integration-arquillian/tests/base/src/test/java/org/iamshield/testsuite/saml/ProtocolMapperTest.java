package org.iamshield.testsuite.saml;

import org.junit.Before;
import org.junit.Test;
import org.iamshield.dom.saml.v2.assertion.AssertionType;
import org.iamshield.dom.saml.v2.assertion.AttributeType;
import org.iamshield.protocol.saml.mappers.AttributeStatementHelper;
import org.iamshield.protocol.saml.mappers.HardcodedAttributeMapper;
import org.iamshield.saml.common.constants.JBossSAMLURIConstants;
import org.iamshield.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.iamshield.testsuite.updaters.ClientAttributeUpdater;
import org.iamshield.testsuite.updaters.ProtocolMappersUpdater;
import org.iamshield.testsuite.util.Matchers;
import org.iamshield.testsuite.util.SamlClient;
import org.iamshield.testsuite.util.SamlClientBuilder;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.iamshield.testsuite.saml.RoleMapperTest.createSamlProtocolMapper;
import static org.iamshield.testsuite.util.SamlStreams.assertionsUnencrypted;
import static org.iamshield.testsuite.util.SamlStreams.attributeStatements;
import static org.iamshield.testsuite.util.SamlStreams.attributesUnecrypted;

/**
 * @author mhajas
 */
public class ProtocolMapperTest extends AbstractSamlTest {

    private ClientAttributeUpdater cau;
    private ProtocolMappersUpdater pmu;

    @Before
    public void cleanMappersAndScopes() {
        this.cau = ClientAttributeUpdater.forClient(adminClient, REALM_NAME, SAML_CLIENT_ID_EMPLOYEE_2)
                .setDefaultClientScopes(Collections.EMPTY_LIST)
                .update();
        this.pmu = cau.protocolMappers()
                .clear()
                .update();

        getCleanup(REALM_NAME)
                .addCleanup(this.cau)
                .addCleanup(this.pmu);
    }

    @Test
    public void hardcodedAttributeMapperWithNullValueTest() throws Exception {
        pmu.add(
                createSamlProtocolMapper(HardcodedAttributeMapper.PROVIDER_ID,
                        AttributeStatementHelper.SAML_ATTRIBUTE_NAME, "HARDCODED_ATTRIBUTE",
                        AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT, AttributeStatementHelper.BASIC,
                        HardcodedAttributeMapper.ATTRIBUTE_VALUE, null
                )
        ).update();


        SAMLDocumentHolder samlResponse = new SamlClientBuilder()
                .authnRequest(getAuthServerSamlEndpoint(REALM_NAME), SAML_CLIENT_ID_EMPLOYEE_2, RoleMapperTest.SAML_ASSERTION_CONSUMER_URL_EMPLOYEE_2, SamlClient.Binding.POST)
                .build()
                .login().user(bburkeUser).build()
                .getSamlResponse(SamlClient.Binding.POST);

        assertThat(samlResponse.getSamlObject(), Matchers.isSamlResponse(JBossSAMLURIConstants.STATUS_SUCCESS));

        Stream<AssertionType> assertions = assertionsUnencrypted(samlResponse.getSamlObject());
        Stream<AttributeType> attributes = attributesUnecrypted(attributeStatements(assertions));
        Set<Object> attributeValues = attributes
                .flatMap(a -> a.getAttributeValue().stream())
                .collect(Collectors.toSet());

        assertThat(attributeValues, hasSize(1));
        assertThat(attributeValues.iterator().next(), nullValue());
    }
}
