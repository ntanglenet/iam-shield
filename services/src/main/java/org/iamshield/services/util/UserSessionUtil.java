package org.iamshield.services.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.iamshield.common.ClientConnection;
import org.iamshield.common.Profile;
import org.iamshield.common.constants.ServiceAccountConstants;
import org.iamshield.events.Errors;
import org.iamshield.models.AuthenticatedClientSessionModel;
import org.iamshield.models.ClientModel;
import org.iamshield.models.Constants;
import org.iamshield.models.ImpersonationSessionNote;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.models.utils.UserSessionModelDelegate;
import org.iamshield.protocol.oidc.OIDCLoginProtocol;
import org.iamshield.protocol.oidc.TokenManager;
import org.iamshield.protocol.oidc.encode.AccessTokenContext;
import org.iamshield.protocol.oidc.encode.TokenContextEncoderProvider;
import org.iamshield.representations.AccessToken;
import org.iamshield.representations.RefreshToken;
import org.iamshield.services.Urls;
import org.iamshield.services.managers.AuthenticationManager;
import org.iamshield.services.managers.UserSessionManager;
import org.iamshield.sessions.AuthenticationSessionModel;
import org.iamshield.sessions.RootAuthenticationSessionModel;
import org.iamshield.util.TokenUtil;

public class UserSessionUtil {

    private static final Logger logger = Logger.getLogger(UserSessionUtil.class);

    public static UserSessionValidationResult findValidSessionForIdentityCookie(IAMShieldSession session, RealmModel realm, AccessToken token, Consumer<UserSessionModel> invalidSessionCallback) {
        return findValidSession(session, realm, token,  null, AccessTokenContext.SessionType.ONLINE, false, true, invalidSessionCallback);
    }


    public static UserSessionValidationResult findValidSessionForRefreshToken(IAMShieldSession session, RealmModel realm, RefreshToken token, ClientModel client, Consumer<UserSessionModel> invalidSessionCallback) {
        AccessTokenContext.SessionType sessionType;
        if (TokenUtil.TOKEN_TYPE_OFFLINE.equals(token.getType())) {
            sessionType = AccessTokenContext.SessionType.OFFLINE;
        } else if (TokenUtil.TOKEN_TYPE_REFRESH.equals(token.getType())) {
            sessionType = AccessTokenContext.SessionType.ONLINE;
        } else {
            return UserSessionValidationResult.error(Errors.INVALID_TOKEN_TYPE);
        }

        return findValidSession(session, realm, token, client, sessionType, Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE), false, invalidSessionCallback);
    }


    public static UserSessionValidationResult findValidSessionForAccessToken(IAMShieldSession session, RealmModel realm, AccessToken token, ClientModel client, Consumer<UserSessionModel> invalidSessionCallback) {
        AccessTokenContext accessTokenContext = session.getProvider(TokenContextEncoderProvider.class).getTokenContextFromTokenId(token.getId());
        AccessTokenContext.SessionType sessionType = accessTokenContext.getSessionType();
        return findValidSession(session, realm, token, client, sessionType, Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE), false, invalidSessionCallback);
    }

    /**
     * Find valid user session (online or offline according to which one is allowed) and performs all the needed checks on it. Like checking if the userSession is valid and if clientSession is attached to it and
     * if userSession (and clientSession) are started earlier than the token.
     *
     * User session will be set to IAMShieldContext if successfully found and verified
     *
     * @param session must be not null
     * @param realm must be not null
     * @param token must be not null
     * @param client must be not null unless "skipCheckClient" is true
     * @param sessionType sessionType from the token. It allows to hint whether session can be looked-up as "online" session or as offline session. Also whether it is allowed to have transient user session or "link" transient client session to the found userSession
     * @param allowImpersonationFallback If true, it is possible to have impersonationCallback in which case the client is not required to be present in the userSession as long as the userSession was involved in impersonation
     * @param skipCheckClient whether the method should skip lookup of clientSession from userSession. Usually when the passed token is not linked to any client (EG. identity cookie)
     * @param invalidSessionCallback Callback, which is invoked when user session is found, but validation of this userSession failed. Callback not called when userSession not found or when all valiation successful
     * @return userSession with all the successful validations OR error. Result should never contain both session and error. The error contains the error code from {@link Errors}, so it can be directly used in the error event
     */
    private static UserSessionValidationResult findValidSession(IAMShieldSession session, RealmModel realm,
                                                    AccessToken token, ClientModel client,
                                                    AccessTokenContext.SessionType sessionType, boolean allowImpersonationFallback, boolean skipCheckClient, Consumer<UserSessionModel> invalidSessionCallback) {
        logger.tracef("Lookup user session with the sessionType '%s'. Token session id: %s", sessionType, token.getSessionId());
        if (token.getSessionId() == null) {
            if (sessionType.isAllowTransientUserSession()) {
                return createTransientSessionForClient(session, realm, token, client);
            } else {
                return UserSessionValidationResult.error(Errors.USER_SESSION_NOT_FOUND);
            }
        }

        var userSessionProvider = session.sessions();

        UserSessionModel userSession = null;
        if (sessionType.isAllowLookupOnlineUserSession()) {
            AuthenticatedClientSessionModel clientSession = null;
            if (skipCheckClient || sessionType.isAllowTransientClientSession()) {
                userSession = userSessionProvider.getUserSession(realm, token.getSessionId());
            } else {
                userSession = userSessionProvider.getUserSessionIfClientExists(realm, token.getSessionId(), false, client.getId());
                if (userSession != null) {
                    clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
                    if (!checkTokenIssuedAt(token, clientSession)) {
                        return UserSessionValidationResult.error(Errors.INVALID_TOKEN, userSession, invalidSessionCallback);
                    }
                }
                if (userSession == null && allowImpersonationFallback) {
                    // also try to resolve sessions created during token exchange when the user is impersonated
                    userSession = getUserSessionWithImpersonatorClient(session, realm, token.getSessionId(), false, client.getId());
                }
            }

            if (AuthenticationManager.isSessionValid(realm, userSession)) {
                if (!checkTokenIssuedAt(token, userSession)) {
                    return UserSessionValidationResult.error(Errors.INVALID_TOKEN, userSession, invalidSessionCallback);
                }

                if (sessionType.isAllowTransientClientSession()) {
                    userSession = createTransientSessionForClient(session, userSession, client);
                    return UserSessionValidationResult.validSession(session, userSession);
                } else {
                    return UserSessionValidationResult.validSession(session, userSession);
                }

            }
        }

        UserSessionModel offlineUserSession = null;
        if (sessionType.isAllowLookupOfflineUserSession()) {
            AuthenticatedClientSessionModel offlineClientSession = null;
            if (sessionType.isAllowTransientClientSession()) {
                offlineUserSession = userSessionProvider.getOfflineUserSession(realm, token.getSessionId());
            } else {
                offlineUserSession = userSessionProvider.getUserSessionIfClientExists(realm, token.getSessionId(), true, client.getId());
                if (offlineUserSession != null) {
                    offlineClientSession = offlineUserSession.getAuthenticatedClientSessionByClient(client.getId());
                    if (!checkTokenIssuedAt(token, offlineClientSession)) {
                        return UserSessionValidationResult.error(Errors.INVALID_TOKEN, offlineUserSession, invalidSessionCallback);
                    }
                }
            }

            if (AuthenticationManager.isSessionValid(realm, offlineUserSession)) {
                if (!checkTokenIssuedAt(token, offlineUserSession)) {
                    return UserSessionValidationResult.error(Errors.INVALID_TOKEN, offlineUserSession, invalidSessionCallback);
                }

                if (sessionType.isAllowTransientClientSession()) {
                    offlineUserSession = createTransientSessionForClient(session, offlineUserSession, client);
                    return UserSessionValidationResult.validSession(session, offlineUserSession);
                } else {
                    return UserSessionValidationResult.validSession(session, offlineUserSession);
                }
            }
        }

        if (userSession == null && offlineUserSession == null) {
            logger.debugf("User session '%s' not found or doesn't have client attached on it", token.getSessionId());
            return UserSessionValidationResult.error(Errors.USER_SESSION_NOT_FOUND);
        }

        logger.debugf("Session '%s' expired", token.getSessionId());
        return UserSessionValidationResult.error(Errors.SESSION_EXPIRED, userSession != null ? userSession : offlineUserSession, invalidSessionCallback);
    }


    public static UserSessionModel createTransientUserSession(IAMShieldSession session, UserSessionModel userSession) {
        if (userSession.getPersistenceState() == UserSessionModel.SessionPersistenceState.TRANSIENT) {
            throw new IllegalArgumentException("Not expected to invoke this method with the transient session");
        }

        UserSessionModel transientSession = new UserSessionManager(session).createUserSession(userSession.getId(), userSession.getRealm(),
                userSession.getUser(), userSession.getLoginUsername(), userSession.getIpAddress(), userSession.getAuthMethod(), userSession.isRememberMe(),
                userSession.getBrokerSessionId(), userSession.getBrokerUserId(), UserSessionModel.SessionPersistenceState.TRANSIENT);
        userSession.getNotes().entrySet().forEach(e -> transientSession.setNote(e.getKey(), e.getValue()));

        String noteValue = userSession.isOffline() ? Constants.CREATED_FROM_PERSISTENT_OFFLINE : Constants.CREATED_FROM_PERSISTENT_ONLINE;
        transientSession.setNote(Constants.CREATED_FROM_PERSISTENT, noteValue);

        // Use "started" time from the original session
        return new UserSessionModelDelegate(transientSession) {

            @Override
            public int getStarted() {
                return userSession.getStarted();
            }

        };
    }

    private static void attachAuthenticationSession(IAMShieldSession session, UserSessionModel userSession, ClientModel client) {
        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(userSession.getRealm());
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(userSession.getUser());
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), userSession.getRealm().getName()));
        AuthenticationManager.setClientScopesInSession(session, authSession);
        TokenManager.attachAuthenticationSession(session, userSession, authSession);
    }

    private static UserSessionModel createTransientSessionForClient(IAMShieldSession session, UserSessionModel userSession, ClientModel client) {
        UserSessionModel transientSession = createTransientUserSession(session, userSession);
        attachAuthenticationSession(session, transientSession, client);
        return transientSession;
    }

    private static UserSessionValidationResult createTransientSessionForClient(IAMShieldSession session, RealmModel realm, AccessToken token, ClientModel client) {
        // create a transient session
        UserModel user = TokenManager.lookupUserFromStatelessToken(session, realm, token);
        if (user == null) {
            logger.debug("Transient User not found");
            return UserSessionValidationResult.error(Errors.USER_NOT_FOUND);
        }
        if (!user.isEnabled()) {
            logger.debugf("User '%s' disabled", user.getUsername());
            return UserSessionValidationResult.error(Errors.USER_DISABLED);
        }

        ClientConnection clientConnection = session.getContext().getConnection();
        UserSessionModel userSession = new UserSessionManager(session).createUserSession(IAMShieldModelUtils.generateId(), realm, user, user.getUsername(), clientConnection.getRemoteHost(),
                ServiceAccountConstants.CLIENT_AUTH, false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);
        // attach an auth session for the client
        attachAuthenticationSession(session, userSession, client);
        return UserSessionValidationResult.validSession(session, userSession);
    }

    private static boolean checkTokenIssuedAt(AccessToken token, UserSessionModel userSession) {
        if (token.isIssuedBeforeSessionStart(userSession.getStarted())) {
            logger.debug("Stale token for user session");
            return false;
        } else {
            return true;
        }
    }

    private static boolean checkTokenIssuedAt(AccessToken token, AuthenticatedClientSessionModel clientSession) {
        if (token.isIssuedBeforeSessionStart(clientSession.getStarted())) {
            logger.debug("Stale token for client session");
            return false;
        } else {
            return true;
        }
    }

    public static UserSessionModel getUserSessionWithImpersonatorClient(IAMShieldSession session, RealmModel realm, String userSessionId, boolean offline, String clientUUID) {
        return session.sessions().getUserSessionWithPredicate(realm, userSessionId, offline, userSession -> Objects.equals(clientUUID, userSession.getNote(ImpersonationSessionNote.IMPERSONATOR_CLIENT.toString())));
    }


    public static class UserSessionValidationResult {
        private final UserSessionModel userSession;
        private final String error;

        private static UserSessionValidationResult validSession(IAMShieldSession session, UserSessionModel userSession) {
            session.getContext().setUserSession(userSession);
            return new UserSessionValidationResult(userSession, null);
        }

        private static UserSessionValidationResult error(String error) {
            return new UserSessionValidationResult(null, error);
        }

        private static UserSessionValidationResult error(String error, UserSessionModel invalidUserSession, Consumer<UserSessionModel> invalidSessionCallback) {
            invalidSessionCallback.accept(invalidUserSession);
            return new UserSessionValidationResult(null, error);
        }

        // Should be only called by static creators
        private UserSessionValidationResult(UserSessionModel userSession, String error) {
            this.userSession = userSession;
            this.error = error;
        }

        public UserSessionModel getUserSession() {
            return userSession;
        }

        public String getError() {
            return error;
        }
    }
}
