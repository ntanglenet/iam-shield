package org.iamshield.protocol.docker;

import org.jboss.logging.Logger;
import org.iamshield.common.Profile;
import org.iamshield.events.EventBuilder;
import org.iamshield.events.EventType;
import org.iamshield.models.AuthenticationFlowModel;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.UserSessionModel;
import org.iamshield.protocol.AuthorizationEndpointBase;
import org.iamshield.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.iamshield.protocol.oidc.endpoints.request.AuthorizationEndpointRequestParserProcessor;
import org.iamshield.services.ErrorResponseException;
import org.iamshield.services.Urls;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.util.CacheControlUtil;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.sessions.CommonClientSessionModel;
import org.iamshield.utils.ProfileHelper;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * Implements a docker-client understandable format.
 */
public class DockerEndpoint extends AuthorizationEndpointBase {
    protected static final Logger logger = Logger.getLogger(DockerEndpoint.class);

    private final EventType login;
    private String account;
    private String service;
    private String scope;
    private ClientModel client;
    private AuthenticationSessionModel authenticationSession;

    public DockerEndpoint(IAMShieldSession session, final EventBuilder event, final EventType login) {
        super(session, event);
        this.login = login;
    }

    @GET
    public Response build() {
        ProfileHelper.requireFeature(Profile.Feature.DOCKER);

        final MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();

        account = params.getFirst(DockerAuthV2Protocol.ACCOUNT_PARAM);
        if (account == null) {
            logger.debug("Account parameter not provided by docker auth.  This is techincally required, but not actually used since " +
                    "username is provided by Basic auth header.");
        }
        service = params.getFirst(DockerAuthV2Protocol.SERVICE_PARAM);
        if (service == null) {
            throw new ErrorResponseException("invalid_request", "service parameter must be provided", Response.Status.BAD_REQUEST);
        }
        client = realm.getClientByClientId(service);
        if (client == null) {
            logger.errorv("Failed to lookup client given by service={0} parameter for realm: {1}.", service, realm.getName());
            throw new ErrorResponseException("invalid_client", "Client specified by 'service' parameter does not exist", Response.Status.BAD_REQUEST);
        }
        session.getContext().setClient(client);
        scope = params.getFirst(DockerAuthV2Protocol.SCOPE_PARAM);

        checkSsl();
        checkRealm();

        final AuthorizationEndpointRequest authRequest = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, client, params, AuthorizationEndpointRequestParserProcessor.EndpointType.DOCKER_ENDPOINT);
        authenticationSession = createAuthenticationSession(client, authRequest.getState());

        updateAuthenticationSession();

        // So back button doesn't work
        CacheControlUtil.noBackButtonCacheControlHeader(session);

        return handleBrowserAuthenticationRequest(authenticationSession, new DockerAuthV2Protocol(session, realm, session.getContext().getUri(), headers, event.event(login)), false, false);
    }

    private void updateAuthenticationSession() {
        authenticationSession.setProtocol(DockerAuthV2Protocol.LOGIN_PROTOCOL);
        authenticationSession.setAction(CommonClientSessionModel.Action.AUTHENTICATE.name());

        // Use transient userSession for the docker protocol. There is no need to persist session as there is no endpoint for "refresh token" or "introspection"
        authenticationSession.setClientNote(AuthenticationManager.USER_SESSION_PERSISTENT_STATE, UserSessionModel.SessionPersistenceState.TRANSIENT.toString());

        // Docker specific stuff
        authenticationSession.setClientNote(DockerAuthV2Protocol.ACCOUNT_PARAM, account);
        authenticationSession.setClientNote(DockerAuthV2Protocol.SERVICE_PARAM, service);
        authenticationSession.setClientNote(DockerAuthV2Protocol.SCOPE_PARAM, scope);
        authenticationSession.setClientNote(DockerAuthV2Protocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

    }

    @Override
    protected AuthenticationFlowModel getAuthenticationFlow(AuthenticationSessionModel authSession) {
        return realm.getDockerAuthenticationFlow();
    }

}
