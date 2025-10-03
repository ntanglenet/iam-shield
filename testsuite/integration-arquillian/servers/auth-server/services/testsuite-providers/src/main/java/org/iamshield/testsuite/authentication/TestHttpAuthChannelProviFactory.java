/*
 *
 *  * Copyright 2021  Red Hat, Inc. and/or its affiliates
 *  * and other contributors as indicated by the @author tags.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.iamshield.testsuite.authentication;

import org.iamshield.Config;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.protocol.oidc.grants.ciba.channel.AuthenticationChannelProvider;
import org.iamshield.protocol.oidc.grants.ciba.channel.HttpAuthenticationChannelProvider;
import org.iamshield.protocol.oidc.grants.ciba.channel.HttpAuthChannelProviFactory;
import org.iamshield.testsuite.util.ServerURLs;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class TestHttpAuthChannelProviFactory extends HttpAuthChannelProviFactory {

    private static final String TEST_HTTP_AUTH_CHANNEL =
            String.format("%s://%s:%s/auth/realms/master/app/oidc-client-endpoints/request-authentication-channel",
                    ServerURLs.AUTH_SERVER_SCHEME, ServerURLs.AUTH_SERVER_HOST, ServerURLs.AUTH_SERVER_PORT);

    @Override
    public AuthenticationChannelProvider create(IAMShieldSession session) {
        return new HttpAuthenticationChannelProvider(session, TEST_HTTP_AUTH_CHANNEL);
    }

    @Override
    public int order() {
        return 100;
    }

    @Override
    public String getId() {
        return "test-http-auth-channel";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return true;
    }
}
