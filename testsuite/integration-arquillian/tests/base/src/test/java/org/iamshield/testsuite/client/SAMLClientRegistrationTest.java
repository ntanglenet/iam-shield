/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.iamshield.testsuite.client;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.iamshield.admin.client.resource.ClientsResource;
import org.iamshield.client.registration.Auth;
import org.iamshield.client.registration.ClientRegistrationException;
import org.iamshield.protocol.saml.SamlConfigAttributes;
import org.iamshield.protocol.saml.SamlProtocol;
import org.iamshield.protocol.saml.mappers.AttributeStatementHelper;
import org.iamshield.protocol.saml.util.ArtifactBindingUtils;
import org.iamshield.representations.idm.ClientInitialAccessCreatePresentation;
import org.iamshield.representations.idm.ClientInitialAccessPresentation;
import org.iamshield.representations.idm.ClientRepresentation;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.testsuite.Assert;
import org.iamshield.testsuite.util.IAMShieldModelUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.iamshield.testsuite.auth.page.AuthRealm.TEST;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class SAMLClientRegistrationTest extends AbstractClientRegistrationTest {

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        super.addTestRealms(testRealms);
        RealmRepresentation testRealm = testRealms.get(0);

        ClientRepresentation samlApp = IAMShieldModelUtils.createClient(testRealm, "oidc-client");
        samlApp.setSecret("secret");
        samlApp.setServiceAccountsEnabled(true);
        samlApp.setDirectAccessGrantsEnabled(true);
    }

    @Before
    public void before() throws Exception {
        super.before();

        ClientInitialAccessPresentation token = adminClient.realm(REALM_NAME).clientInitialAccess().create(new ClientInitialAccessCreatePresentation(0, 10));
        reg.auth(Auth.token(token));
    }

    @Test
    public void createClient() throws ClientRegistrationException, IOException {
        String entityDescriptor = IOUtils.toString(getClass().getResourceAsStream("/clientreg-test/saml-entity-descriptor.xml"), Charset.defaultCharset());
        assertClientCreation(entityDescriptor);
    }

    @Test
    public void testSAMLEndpointCreateWithOIDCClient() throws Exception {
        ClientsResource clientsResource = adminClient.realm(TEST).clients();
        ClientRepresentation oidcClient = clientsResource.findByClientId("oidc-client").get(0);
        String oidcClientServiceId = clientsResource.get(oidcClient.getId()).getServiceAccountUser().getId();

        String realmManagementId = clientsResource.findByClientId("realm-management").get(0).getId();
        RoleRepresentation role = clientsResource.get(realmManagementId).roles().get("create-client").toRepresentation();

        adminClient.realm(TEST).users().get(oidcClientServiceId).roles().clientLevel(realmManagementId).add(Arrays.asList(role));

        String accessToken = oauth.client("oidc-client", "secret").doClientCredentialsGrantAccessTokenRequest().getAccessToken();
        reg.auth(Auth.token(accessToken));

        String entityDescriptor = IOUtils.toString(getClass().getResourceAsStream("/clientreg-test/saml-entity-descriptor.xml"), Charset.defaultCharset());
        assertClientCreation(entityDescriptor);
    }

    private void assertClientCreation(String entityDescriptor) throws ClientRegistrationException {
        ClientRepresentation response = reg.saml().create(entityDescriptor);
        assertThat(response.getRegistrationAccessToken(), notNullValue());
        assertThat(response.getClientId(), is("loadbalancer-9.siroe.com"));
        assertThat(response.getRedirectUris(), containsInAnyOrder(
                "https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp/post",
                "https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp/soap",
                "https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp/paos",
                "https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp/redirect",
                "https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp/artifact"
        ));

        assertThat(response.getAttributes().get(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE), is("https://LoadBalancer-9.siroe.com:3443/federation/SPSloRedirect/metaAlias/sp"));
        assertThat(response.getAttributes().get(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_ATTRIBUTE), is("https://LoadBalancer-9.siroe.com:3443/federation/SPSloSoap/metaAlias/sp"));
        assertThat(response.getAttributes().get(SamlConfigAttributes.SAML_ARTIFACT_BINDING_IDENTIFIER), is(ArtifactBindingUtils.computeArtifactBindingIdentifierString("loadbalancer-9.siroe.com")));

        Assert.assertNotNull(response.getProtocolMappers());
        Assert.assertEquals(1,response.getProtocolMappers().size());
        ProtocolMapperRepresentation mapper = response.getProtocolMappers().get(0);
        Assert.assertEquals("saml-user-attribute-mapper",mapper.getProtocolMapper());
        Assert.assertEquals("urn:oid:2.5.4.42",mapper.getConfig().get(AttributeStatementHelper.SAML_ATTRIBUTE_NAME));
        Assert.assertEquals("givenName",mapper.getConfig().get(AttributeStatementHelper.FRIENDLY_NAME));
        Assert.assertEquals(AttributeStatementHelper.URI_REFERENCE,mapper.getConfig().get(AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT));

        adminClient.realm(REALM_NAME).clients().get(response.getId()).remove();
    }
}
