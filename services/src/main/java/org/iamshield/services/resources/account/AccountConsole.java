package org.iamshield.services.resources.account;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.NoCache;
import org.iamshield.authentication.requiredactions.DeleteAccount;
import org.iamshield.authentication.requiredactions.UpdateEmail;
import org.iamshield.common.Profile;
import org.iamshield.common.Version;
import org.iamshield.common.util.Environment;
import org.iamshield.models.FederatedIdentityModel;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.IdentityProviderStorageProvider;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.utils.SecureContextResolver;
import org.iamshield.models.AccountRoles;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RoleModel;
import org.iamshield.models.UserModel;
import org.iamshield.protocol.oidc.utils.RedirectUtils;
import org.iamshield.services.Urls;
import org.iamshield.services.managers.AppAuthManager;
import org.iamshield.services.managers.Auth;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.resource.AccountResourceProvider;
import org.iamshield.services.resources.RealmsResource;
import org.iamshield.services.util.ResolveRelative;
import org.iamshield.services.util.ViteManifest;
import org.iamshield.services.validation.Validation;
import org.iamshield.theme.FreeMarkerException;
import org.iamshield.theme.Theme;
import org.iamshield.theme.beans.MessageFormatterMethod;
import org.iamshield.theme.freemarker.FreeMarkerProvider;
import org.iamshield.urls.UrlType;
import org.iamshield.util.JsonSerialization;
import org.iamshield.utils.MediaType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by st on 29/03/17.
 */
public class AccountConsole implements AccountResourceProvider {

    private final Pattern bundleParamPattern = Pattern.compile("(\\{\\s*(\\d+)\\s*\\})");

    protected final IAMShieldSession session;

    private final AppAuthManager authManager;
    private final RealmModel realm;
    private final ClientModel client;
    private final Theme theme;

    private Auth auth;

    public AccountConsole(IAMShieldSession session, ClientModel client, Theme theme) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.client = client;
        this.theme = theme;
        this.authManager = new AppAuthManager();
        init();
    }

    public void init() {
        AuthenticationManager.AuthResult authResult = authManager.authenticateIdentityCookie(session, realm);
        if (authResult != null) {
            auth = new Auth(realm, authResult.getToken(), authResult.getUser(), client, authResult.getSession(), true);
        }
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @GET
    @NoCache
    @Path("{path:.*}")
    public Response getMainPage(@PathParam("path") String path) throws IOException, FreeMarkerException {

        return renderAccountConsole();
    }

    protected Response renderAccountConsole() throws IOException, FreeMarkerException {
        final var serverUriInfo = session.getContext().getUri(UrlType.FRONTEND);
        final var serverBaseUri = serverUriInfo.getBaseUri();
        // Strip any trailing slashes from the URL.
        final var serverBaseUrl = serverBaseUri.toString().replaceFirst("/+$", "");

        final var map = new HashMap<String, Object>();
        final var accountBaseUrl = serverUriInfo.getBaseUriBuilder()
                .path(RealmsResource.class)
                .path(realm.getName())
                .path(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)
                .path("/")
                .build(realm);

        final var isSecureContext = SecureContextResolver.isSecureContext(session);

        map.put("isSecureContext", isSecureContext);
        map.put("serverBaseUrl", serverBaseUrl);
        // TODO: Some variables are deprecated and only exist to provide backwards compatibility for older themes, they should be removed in a future version.
        // Note that these should be removed from the template of the Account Console as well.
        map.put("authUrl", serverBaseUrl + "/"); // Superseded by 'serverBaseUrl', remove in the future.
        map.put("authServerUrl", serverBaseUrl + "/"); // Superseded by 'serverBaseUrl', remove in the future.
        map.put("baseUrl", accountBaseUrl.getPath().endsWith("/") ? accountBaseUrl : accountBaseUrl + "/");
        map.put("realm", realm);
        map.put("clientId", Constants.ACCOUNT_CONSOLE_CLIENT_ID);
        map.put("resourceUrl", Urls.themeRoot(serverBaseUri).getPath() + "/" + Constants.ACCOUNT_MANAGEMENT_CLIENT_ID + "/" + theme.getName());
        map.put("resourceCommonUrl", Urls.themeRoot(serverBaseUri).getPath() + "/common/iamshield");
        map.put("resourceVersion", Version.RESOURCES_VERSION);

        MultivaluedMap<String, String> queryParameters = session.getContext().getUri().getQueryParameters();
        var requestedScopes = queryParameters.getFirst(OIDCLoginProtocol.SCOPE_PARAM);

        if (requestedScopes == null) {
            requestedScopes = AuthenticationManager.getRequestedScopes(session, realm.getClientByClientId(Constants.ACCOUNT_CONSOLE_CLIENT_ID));
        }

        if (requestedScopes != null) {
            map.put(OIDCLoginProtocol.SCOPE_PARAM, requestedScopes);
        }

        String[] referrer = getReferrer();
        if (referrer != null) {
            map.put("referrer", referrer[0]);
            map.put("referrerName", referrer[1]);
            map.put("referrer_uri", referrer[2]);
        }

        UserModel user = null;
        if (auth != null) user = auth.getUser();
        Locale locale = session.getContext().resolveLocale(user);
        map.put("locale", locale.toLanguageTag());
        Properties messages = theme.getEnhancedMessages(realm, locale);
        map.put("msg", new MessageFormatterMethod(locale, messages));
        map.put("msgJSON", messagesToJsonString(messages));
        map.put("supportedLocales", supportedLocales(messages));
        map.put("properties", theme.getProperties());
        map.put("darkMode", "true".equals(theme.getProperties().getProperty("darkMode"))
                && realm.getAttribute("darkMode", true));
        map.put("theme", (Function<String, String>) file -> {
            try {
                final InputStream resource = theme.getResourceAsStream(file);
                return new Scanner(resource, StandardCharsets.UTF_8).useDelimiter("\\A").next();
            } catch (IOException e) {
                throw new RuntimeException("could not load file", e);
            }
        });

        map.put("isAuthorizationEnabled", Profile.isFeatureEnabled(Profile.Feature.AUTHORIZATION));
        map.put("isLinkedAccountsEnabled", isLinkedAccountsEnabled(user));

        boolean deleteAccountAllowed = false;
        boolean isViewGroupsEnabled = false;
        if (user != null) {
            RoleModel deleteAccountRole = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).getRole(AccountRoles.DELETE_ACCOUNT);
            deleteAccountAllowed = deleteAccountRole != null && user.hasRole(deleteAccountRole) && realm.getRequiredActionProviderByAlias(DeleteAccount.PROVIDER_ID).isEnabled();
            RoleModel viewGrouRole = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).getRole(AccountRoles.VIEW_GROUPS);
            isViewGroupsEnabled = viewGrouRole != null && user.hasRole(viewGrouRole);
        }

        map.put("deleteAccountAllowed", deleteAccountAllowed);

        map.put("isViewGroupsEnabled", isViewGroupsEnabled);
        map.put("isViewOrganizationsEnabled", realm.isOrganizationsEnabled());
        map.put("isOid4VciEnabled", realm.isVerifiableCredentialsEnabled());

        map.put("updateEmailFeatureEnabled", Profile.isFeatureEnabled(Profile.Feature.UPDATE_EMAIL));
        map.put("updateEmailActionEnabled", UpdateEmail.isEnabled(realm));

        final var devServerUrl = Environment.isDevMode() ? System.getenv(ViteManifest.ACCOUNT_VITE_URL) : null;

        if (devServerUrl != null) {
            map.put("devServerUrl", devServerUrl);
        }

        final var manifestFile = theme.getResourceAsStream(ViteManifest.MANIFEST_FILE_PATH);

        if (devServerUrl == null && manifestFile != null) {
            final var manifest = ViteManifest.parseFromInputStream(manifestFile);
            final var entryChunk = manifest.getEntryChunk();
            final var entryStyles = entryChunk.css().orElse(new String[] {});
            final var entryScript = entryChunk.file();
            final var entryImports = entryChunk.imports().orElse(new String[] {});

            map.put("entryStyles", entryStyles);
            map.put("entryScript", entryScript);
            map.put("entryImports", entryImports);
        }

        FreeMarkerProvider freeMarkerUtil = session.getProvider(FreeMarkerProvider.class);
        String result = renderAccountConsole(freeMarkerUtil, map);
        Response.ResponseBuilder builder = Response.status(Response.Status.OK).type(MediaType.TEXT_HTML_UTF_8).language(Locale.ENGLISH).entity(result);
        return builder.build();
    }

    protected String renderAccountConsole(FreeMarkerProvider freeMarkerUtil, Map<String, Object> map) throws FreeMarkerException {
        return freeMarkerUtil.processTemplate(map, "index.ftl", theme);
    }

    protected Map<String, String> supportedLocales(Properties messages) {
        return realm.getSupportedLocalesStream()
                .collect(Collectors.toMap(Function.identity(), l -> messages.getProperty("locale_" + l, l)));
    }

    protected String messagesToJsonString(Properties props) {
        if (props == null) return "";
        Properties newProps = new Properties();
        for (String prop : props.stringPropertyNames()) {
            newProps.put(prop, convertPropValue(props.getProperty(prop)));
        }
        try {
            return JsonSerialization.writeValueAsString(newProps);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String convertPropValue(String propertyValue) {
        // this mimics the behavior of java.text.MessageFormat used for the freemarker templates:
        // To print a single quote one needs to write two single quotes.
        // Single quotes will be stripped.
        // Usually single quotes would escape parameters, but this not implemented here.
        propertyValue = propertyValue.replaceAll("'('?)", "$1");
        propertyValue = putJavaParamsInNgTranslateFormat(propertyValue);

        return propertyValue;
    }

    // Put java resource bundle params in ngx-translate format
    // Do you like {0} and {1} ?
    //    becomes
    // Do you like {{param_0}} and {{param_1}} ?
    private String putJavaParamsInNgTranslateFormat(String propertyValue) {
        Matcher matcher = bundleParamPattern.matcher(propertyValue);
        while (matcher.find()) {
            propertyValue = propertyValue.replace(matcher.group(1), "{{param_" + matcher.group(2) + "}}");
        }

        return propertyValue;
    }

    @GET
    @Path("index.html")
    public Response getIndexHtmlRedirect() {
        return Response.status(302).location(session.getContext().getUri().getRequestUriBuilder().path("../").build()).build();
    }

    private String[] getReferrer() {
        String referrer = session.getContext().getUri().getQueryParameters().getFirst("referrer");

        if (referrer == null) {
            return null;
        }

        ClientModel referrerClient = realm.getClientByClientId(referrer);

        if (referrerClient == null) {
            return null;
        }

        String referrerUri = session.getContext().getUri().getQueryParameters().getFirst("referrer_uri");

        if (referrerUri != null) {
            referrerUri = RedirectUtils.verifyRedirectUri(session, referrerUri, referrerClient);
        } else {
            referrerUri = ResolveRelative.resolveRelativeUri(session, referrerClient.getRootUrl(), referrerClient.getBaseUrl());
        }

        if (referrerUri == null) {
            return null;
        }

        String referrerName = referrerClient.getName();

        if (Validation.isBlank(referrerName)) {
            referrerName = referrer;
        }

        return new String[]{referrer, referrerName, referrerUri};
    }

    protected boolean isLinkedAccountsEnabled(UserModel user) {
        if (user == null) {
            return false;
        }

        IdentityProviderStorageProvider identityProviders = session.identityProviders();
        Stream<IdentityProviderModel> realmBrokers = identityProviders.getAllStream(Map.of(
                IdentityProviderModel.ENABLED, "true",
                IdentityProviderModel.ORGANIZATION_ID, ""), 0, 1);
        Stream<IdentityProviderModel> linkedBrokers = session.users().getFederatedIdentitiesStream(realm, user)
                .map(FederatedIdentityModel::getIdentityProvider)
                .map(identityProviders::getByAlias);

        return Stream.concat(realmBrokers, linkedBrokers).findAny().isPresent();
    }
}
