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
package org.iamshield.testsuite.script;

import static org.junit.Assert.assertTrue;
import static org.iamshield.common.Profile.Feature.SCRIPTS;
import static org.iamshield.testsuite.admin.ApiUtil.findClientResourceByClientId;
import static org.iamshield.testsuite.arquillian.DeploymentTargetModifier.AUTH_SERVER_CURRENT;
import static org.iamshield.testsuite.util.ProtocolMapperUtil.createScriptMapper;

import java.io.IOException;

import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.iamshield.admin.client.resource.ClientResource;
import org.iamshield.representations.idm.ProtocolMapperRepresentation;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.representations.provider.ScriptProviderDescriptor;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.arquillian.annotation.EnableFeature;
import org.iamshield.testsuite.util.ContainerAssume;
import org.iamshield.util.JsonSerialization;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UndeployedScriptMapperNotAvailableTest extends AbstractTestRealmIAMShieldTest {

    private static final String SCRIPT_DEPLOYMENT_NAME = "scripts.jar";

    @Deployment(name = SCRIPT_DEPLOYMENT_NAME, managed = false, testable = false)
    @TargetsContainer(AUTH_SERVER_CURRENT)
    public static JavaArchive deploy() throws IOException {
        ScriptProviderDescriptor representation = new ScriptProviderDescriptor();

        representation.addMapper("My Mapper", "mapper-a.js");

        return ShrinkWrap.create(JavaArchive.class, SCRIPT_DEPLOYMENT_NAME)
                .addAsManifestResource(new StringAsset(JsonSerialization.writeValueAsPrettyString(representation)),
                        "iamshield-scripts.json")
                .addAsResource("scripts/mapper-example.js", "mapper-a.js");
    }

    @BeforeClass
    public static void verifyEnvironment() {
        ContainerAssume.assumeNotAuthServerUndertow();
    }

    @ArquillianResource
    private Deployer deployer;

    @Before
    public void configureFlows() throws Exception {
        deployer.deploy(SCRIPT_DEPLOYMENT_NAME);
        reconnectAdminClient();
    }

    @After
    public void onAfter() throws Exception {
        deployer.undeploy(SCRIPT_DEPLOYMENT_NAME);
        reconnectAdminClient();
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {

    }

    @Test
    @EnableFeature(value = SCRIPTS, skipRestart = true, executeAsLast = false)
    public void testMapperNotRecognizedWhenDisabled() throws Exception {
        ClientResource app = findClientResourceByClientId(adminClient.realm("test"), "test-app");
        {
            ProtocolMapperRepresentation mapper = createScriptMapper("test-script-mapper1", "computed-via-script",
                    "computed-via-script", "String", true, true, true, "'hello_' + user.username", false);

            mapper.setProtocolMapper("script-mapper-a.js");

            app.getProtocolMappers().createMapper(mapper).close();
        }
        deployer.undeploy(SCRIPT_DEPLOYMENT_NAME);
        reconnectAdminClient();
        ClientResource cl = findClientResourceByClientId(adminClient.realm("test"), "test-app");
        assertTrue(cl.getProtocolMappers().getMappers().isEmpty());
        assertTrue(cl.getProtocolMappers().getMappersPerProtocol(cl.toRepresentation().getProtocol()).isEmpty());
    }
}
