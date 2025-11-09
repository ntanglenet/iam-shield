package org.iamshield.protocol.docker;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.jaxrs.ResponseBuilderImpl;
import org.iamshield.authentication.AuthenticationFlowContext;
import org.iamshield.authentication.AuthenticationFlowError;
import org.iamshield.events.Errors;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.protocol.saml.profile.ecp.authenticator.HttpBasicAuthenticator;
import org.iamshield.representations.docker.DockerAccess;
import org.iamshield.representations.docker.DockerError;
import org.iamshield.representations.docker.DockerErrorResponseToken;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;

public class DockerAuthenticator extends HttpBasicAuthenticator {
    private static final Logger logger = Logger.getLogger(DockerAuthenticator.class);

    public static final String ID = "docker-http-basic-authenticator";

    @Override
    protected void notValidCredentialsAction(final AuthenticationFlowContext context, final RealmModel realm, final UserModel user) {
        invalidUserAction(context, realm, user.getUsername(), context.getSession().getContext().resolveLocale(user));
    }

    @Override
    protected void nullUserAction(final AuthenticationFlowContext context, final RealmModel realm, final String userId) {
        final String localeString = Optional.ofNullable(realm.getDefaultLocale()).orElse(Locale.ENGLISH.toString());
        invalidUserAction(context, realm, userId, new Locale(localeString));
    }

    @Override
    protected void userDisabledAction(AuthenticationFlowContext context, RealmModel realm, UserModel user, String eventError) {
        context.getEvent().user(user);
        context.getEvent().error(eventError);
        final DockerError error = new DockerError("UNAUTHORIZED","Invalid username or password.",
                Collections.singletonList(new DockerAccess(context.getAuthenticationSession().getClientNote(DockerAuthV2Protocol.SCOPE_PARAM))));
        context.failure(AuthenticationFlowError.USER_DISABLED, new ResponseBuilderImpl()
                .status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .entity(new DockerErrorResponseToken(Collections.singletonList(error)))
                .build());
    }

    /**
     * For Docker protocol the same error message will be returned for invalid credentials and incorrect user name.  For SAML
     * ECP, there is a different behavior for each.
     */
    private void invalidUserAction(final AuthenticationFlowContext context, final RealmModel realm, final String userId, final Locale locale) {
        context.getEvent().user(userId);
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);

        final DockerError error = new DockerError("UNAUTHORIZED","Invalid username or password.",
                Collections.singletonList(new DockerAccess(context.getAuthenticationSession().getClientNote(DockerAuthV2Protocol.SCOPE_PARAM))));

        context.failure(AuthenticationFlowError.INVALID_USER, new ResponseBuilderImpl()
                .status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .entity(new DockerErrorResponseToken(Collections.singletonList(error)))
                .build());
    }

    @Override
    public boolean configuredFor(IAMShieldSession session, RealmModel realm, UserModel user) {
        return true;
    }
}
