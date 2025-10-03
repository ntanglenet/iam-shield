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
package org.iamshield.quarkus.runtime.services.resources;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.iamshield.common.util.UriUtils;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.quarkus.runtime.Environment;
import org.iamshield.quarkus.runtime.configuration.Configuration;
import org.iamshield.quarkus.runtime.configuration.mappers.HostnameV2PropertyMappers;
import org.iamshield.services.Urls;
import org.iamshield.services.cors.Cors;
import org.iamshield.theme.FreeMarkerException;
import org.iamshield.theme.Theme;
import org.iamshield.theme.freemarker.FreeMarkerProvider;
import org.iamshield.urls.UrlType;
import org.iamshield.utils.SecureContextResolver;

import io.quarkus.resteasy.reactive.server.EndpointDisabled;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

@Provider
@Path("/realms")
@EndpointDisabled(name = "kc.hostname-debug", stringValue = "false", disableIfMissing = true)
public class DebugHostnameSettingsResource {
    public static final String DEFAULT_PATH_SUFFIX = "hostname-debug";
    public static final String PATH_FOR_TEST_CORS_IN_HEADERS = "test";


    @Context
    private IAMShieldSession iamshieldSession;

    private final Map<String, String> allConfigPropertiesMap;

    public DebugHostnameSettingsResource() {

        this.allConfigPropertiesMap = new LinkedHashMap<>();
        String[] relevantOptions = ConstantsDebugHostname.RELEVANT_OPTIONS_V2;
        for (String key : relevantOptions) {
            addOption(key);
        }

    }

    @GET
    @Path("/{realmName}/" + DEFAULT_PATH_SUFFIX)
    @Produces(MediaType.TEXT_HTML)
    public String debug(final @PathParam("realmName") String realmName) throws IOException, FreeMarkerException {
        RealmModel realmModel = iamshieldSession.realms().getRealmByName(realmName);

        if (realmModel == null) {
            throw new NotFoundException();
        }

        FreeMarkerProvider freeMarkerProvider = iamshieldSession.getProvider(FreeMarkerProvider.class);

        List<String> configWarnings = new ArrayList<String>();
        HostnameV2PropertyMappers.validateConfig(configWarnings::add);

        URI frontendUri = iamshieldSession.getContext().getUri(UrlType.FRONTEND).getBaseUri();
        URI backendUri = iamshieldSession.getContext().getUri(UrlType.BACKEND).getBaseUri();
        URI adminUri = iamshieldSession.getContext().getUri(UrlType.ADMIN).getBaseUri();

        String frontendTestUrl = getTest(realmModel, frontendUri, true);
        String backendTestUrl = getTest(realmModel, backendUri, false);
        String adminTestUrl = getTest(realmModel, adminUri, false);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("configWarnings", configWarnings);
        attributes.put("frontendUrl", frontendUri.toString());
        attributes.put("backendUrl", backendUri.toString());
        attributes.put("adminUrl", adminUri.toString());

        attributes.put("realm", realmModel.getName());
        attributes.put("realmUrl", realmModel.getAttribute("frontendUrl"));
        attributes.put("implVersion", "V2");

        attributes.put("frontendTestUrl", frontendTestUrl);
        attributes.put("backendTestUrl", backendTestUrl);
        attributes.put("adminTestUrl", adminTestUrl);

        attributes.put("serverMode", Environment.isDevMode() ? "dev [start-dev]" : "production [start]");

        attributes.put("config", this.allConfigPropertiesMap);
        attributes.put("headers", getHeaders());

        return freeMarkerProvider.processTemplate(
                attributes,
                "debug-hostname-settings.ftl",
                iamshieldSession.theme().getTheme("base", Theme.Type.LOGIN)
        );
    }

    @GET
    @Path("/{realmName}/" + DEFAULT_PATH_SUFFIX + "/" + PATH_FOR_TEST_CORS_IN_HEADERS)
    @Produces(MediaType.TEXT_PLAIN)
    public Response test(final @PathParam("realmName") String realmName, @DefaultValue("false") @QueryParam("frontEnd") boolean frontEnd) {
        String text = "OK";
        String corsOrigin = iamshieldSession.getContext().getRequestHeaders().getHeaderString(Cors.ORIGIN_HEADER);
        URI requestUri = iamshieldSession.getContext().getUri().getRequestUri();
        String requestOrigin = UriUtils.getOrigin(requestUri);
        URI frontendUri = iamshieldSession.getContext().getUri(UrlType.FRONTEND).getBaseUri();

        if (frontEnd) {
            boolean originMatches = requestOrigin.equals(UriUtils.getOrigin(frontendUri));
            HttpHeaders requestHeaders = iamshieldSession.getContext().getRequestHeaders();
            boolean fowarded = requestHeaders.getHeaderString(ConstantsDebugHostname.FORWARDED_PROXY_HEADER) != null;
            boolean xfowarded = Stream.of(ConstantsDebugHostname.X_FORWARDED_PROXY_HEADERS)
                    .map(requestHeaders::getHeaderString).anyMatch(Objects::nonNull);

            if (!originMatches) { // might fail CORS checks
                text = "Default origin check failing, request hostname does not match frontend hostname. Please check you proxy settings.";
                if (!iamshieldSession.getContext().getHttpRequest().isProxyTrusted()) {
                    text += " Note the proxy is not trusted.";
                }
                if (!fowarded && !xfowarded) {
                    text += " No proxy headers are set on the request.";
                }
            }

            boolean https = requestUri.getScheme().equals("https");
            if (https) {
                // if reencrypt, then proxy headers may need set
                // if passthrough, then proxy headers should not be set

                // TODO: not sure if there is great way to do this. Would likely need to check that a connection to the frontend uses the same
                // cert as what is coming in on this request
            } else if (!SecureContextResolver.isSecureContext(iamshieldSession)) {
                text += " Non-secure context detected - Keycloak will not function properly when accessed over http at a non-localhost host.";
            }
        }

        Response.ResponseBuilder builder = Response.ok(text);
        builder.header(Cors.ACCESS_CONTROL_ALLOW_ORIGIN, corsOrigin);
        builder.header(Cors.ACCESS_CONTROL_ALLOW_METHODS, "GET");
        return builder.build();
    }

    private void addOption(String key) {
        Configuration.getOptionalKcValue(key).ifPresent(value -> this.allConfigPropertiesMap.put(key, value));
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new TreeMap<>();
        HttpHeaders requestHeaders = iamshieldSession.getContext().getRequestHeaders();
        for (String h : ConstantsDebugHostname.RELEVANT_HEADERS) {
            addProxyHeader(h, headers, requestHeaders);
        }
        return headers;
    }

    private void addProxyHeader(String header, Map<String, String> proxyHeaders, HttpHeaders requestHeaders) {
        String value = requestHeaders.getHeaderString(header);
        if (value != null && !value.isEmpty()) {
            proxyHeaders.put(header, value);
        }
    }

    private String getTest(RealmModel realmModel, URI baseUri, boolean frontEnd) {
        return Urls.realmBase(baseUri)
                   .path("/{realmName}/{debugHostnameSettingsPath}/{pathForTestCORSInHeaders}")
                   .queryParam("frontEnd", frontEnd)
                   .build(realmModel.getName(), DEFAULT_PATH_SUFFIX, PATH_FOR_TEST_CORS_IN_HEADERS)
                   .toString();
    }

}
