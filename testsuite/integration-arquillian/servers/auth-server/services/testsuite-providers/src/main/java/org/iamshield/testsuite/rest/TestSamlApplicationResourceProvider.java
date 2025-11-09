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

package org.iamshield.testsuite.rest;

import org.iamshield.http.HttpRequest;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.jose.jws.JWSInputException;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.representations.adapters.action.LogoutAction;
import org.iamshield.representations.adapters.action.PushNotBeforeAction;
import org.iamshield.representations.adapters.action.TestAvailabilityAction;
import org.iamshield.services.resource.RealmResourceProvider;
import org.iamshield.services.resources.RealmsResource;
import org.iamshield.utils.MediaType;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Copied from {@link TestApplicationResourceProvider} 
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class TestSamlApplicationResourceProvider implements RealmResourceProvider {

    private final IAMShieldSession session;

    private final BlockingQueue<LogoutAction> adminLogoutActions;
    private final BlockingQueue<PushNotBeforeAction> adminPushNotBeforeActions;
    private final BlockingQueue<TestAvailabilityAction> adminTestAvailabilityAction;

    public TestSamlApplicationResourceProvider(IAMShieldSession session, BlockingQueue<LogoutAction> adminLogoutActions,
            BlockingQueue<PushNotBeforeAction> adminPushNotBeforeActions,
            BlockingQueue<TestAvailabilityAction> adminTestAvailabilityAction) {
        this.session = session;
        this.adminLogoutActions = adminLogoutActions;
        this.adminPushNotBeforeActions = adminPushNotBeforeActions;
        this.adminTestAvailabilityAction = adminTestAvailabilityAction;
    }

    @POST
    @Consumes(MediaType.TEXT_PLAIN_UTF_8)
    @Path("/saml/k_logout")
    public void adminLogout(String data) throws JWSInputException {
        adminLogoutActions.add(new JWSInput(data).readJsonContent(LogoutAction.class));
    }

    @POST
    @Consumes(MediaType.TEXT_PLAIN_UTF_8)
    @Path("/saml/k_push_not_before")
    public void adminPushNotBefore(String data) throws JWSInputException {
        adminPushNotBeforeActions.add(new JWSInput(data).readJsonContent(PushNotBeforeAction.class));
    }

    @POST
    @Consumes(MediaType.TEXT_PLAIN_UTF_8)
    @Path("/saml/k_test_available")
    public void testAvailable(String data) throws JWSInputException {
        adminTestAvailabilityAction.add(new JWSInput(data).readJsonContent(TestAvailabilityAction.class));
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/poll-admin-logout")
    public LogoutAction getAdminLogoutAction() throws InterruptedException {
        return adminLogoutActions.poll(10, TimeUnit.SECONDS);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/poll-admin-not-before")
    public PushNotBeforeAction getAdminPushNotBefore() throws InterruptedException {
        return adminPushNotBeforeActions.poll(10, TimeUnit.SECONDS);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/poll-test-available")
    public TestAvailabilityAction getTestAvailable() throws InterruptedException {
        return adminTestAvailabilityAction.poll(10, TimeUnit.SECONDS);
    }

    @POST
    @Path("/clear-admin-actions")
    public Response clearAdminActions() {
        adminLogoutActions.clear();
        adminPushNotBeforeActions.clear();
        return Response.noContent().build();
    }

    @POST
    @Produces(MediaType.TEXT_HTML_UTF_8)
    @Path("/{action}")
    public String post(@PathParam("action") String action) {
        String title = "APP_REQUEST";
        if (action.equals("auth")) {
            title = "AUTH_RESPONSE";
        } else if (action.equals("logout")) {
            title = "LOGOUT_REQUEST";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><title>" + title + "</title></head><body>");

        sb.append("<b>Form parameters: </b><br>");
        HttpRequest request = session.getContext().getHttpRequest();
        MultivaluedMap<String, String> formParams = request.getDecodedFormParameters();
        for (String paramName : formParams.keySet()) {
            sb.append(paramName).append(": ").append("<span id=\"").append(paramName).append("\">").append(formParams.getFirst(paramName)).append("</span><br>");
        }
        sb.append("<br>");

        UriBuilder base = UriBuilder.fromUri("/auth");
        sb.append("<a href=\"" + RealmsResource.accountUrl(base).build("test").toString() + "\" id=\"account\">account</a>");

        sb.append("</body></html>");
        return sb.toString();
    }

    @GET
    @Produces(MediaType.TEXT_HTML_UTF_8)
    @Path("/{action}")
    public String get(@PathParam("action") String action) {
        //String requestUri = session.getContext().getUri().getRequestUri().toString();

        String title = "APP_REQUEST";
         if (action.equals("auth")) {
            title = "AUTH_RESPONSE";
        } else if (action.equals("logout")) {
            title = "LOGOUT_REQUEST";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><title>" + title + "</title></head><body>");
        UriBuilder base = UriBuilder.fromUri("/auth");
        sb.append("<a href=\"" + RealmsResource.accountUrl(base).build("test").toString() + "\" id=\"account\">account</a>");

        sb.append("</body></html>");
        return sb.toString();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }
}
