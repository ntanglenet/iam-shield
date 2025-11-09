/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.iamshield.quarkus.runtime.integration.resteasy;

import io.vertx.core.http.HttpServerRequest;
import org.jboss.resteasy.reactive.server.core.CurrentRequestManager;
import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;
import org.iamshield.common.ClientConnection;
import org.iamshield.http.HttpRequest;
import org.iamshield.http.HttpResponse;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.services.DefaultIAMShieldContext;

public final class QuarkusIAMShieldContext extends DefaultIAMShieldContext {

    public QuarkusIAMShieldContext(IAMShieldSession session) {
        super(session);
    }

    @Override
    protected HttpRequest createHttpRequest() {
        return new QuarkusHttpRequest(getResteasyReactiveRequestContext());
    }

    @Override
    protected HttpResponse createHttpResponse() {
        return new QuarkusHttpResponse(getResteasyReactiveRequestContext());
    }

    @Override
    protected ClientConnection createClientConnection() {
        ResteasyReactiveRequestContext requestContext = getResteasyReactiveRequestContext();
        HttpServerRequest serverRequest = requestContext.unwrap(HttpServerRequest.class);
        return new QuarkusClientConnection(serverRequest);
    }

    private ResteasyReactiveRequestContext getResteasyReactiveRequestContext() {
        return CurrentRequestManager.get();
    }
}
