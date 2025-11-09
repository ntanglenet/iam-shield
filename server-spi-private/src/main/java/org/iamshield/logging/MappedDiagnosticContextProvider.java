package org.iamshield.logging;

import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.OrganizationModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.provider.Provider;
import org.iamshield.sessions.AuthenticationSessionModel;

/**
 * Provider interface for updating the Mapped Diagnostic Context (MDC) with key/value pairs based on the current keycloak context.
 * All keys in the MDC will be prefixed with "kc." to avoid conflicts.
 *
 * @author <a href="mailto:b.eicki@gmx.net">Björn Eickvonder</a>
 */
public interface MappedDiagnosticContextProvider extends Provider {

    String MDC_PREFIX = "kc.";

    /**
     * Updates the Mapped Diagnostic Context (MDC) with key/value pairs based on the current Keycloak context.
     * This method is called when a Keycloak Session is set and when the authentication session property of the
     * Keycloak context is updated.
     *
     * @param keycloakContext the current Keycloak context, never null
     * @param session the authentication session
     */
    void update(IAMShieldContext keycloakContext, AuthenticationSessionModel session);

    /**
     * Updates the Mapped Diagnostic Context (MDC) with key/value pairs based on the current Keycloak context.
     * This method is called when a Keycloak Session is set and when the realm property of the Keycloak context
     * is updated.
     *
     * @param keycloakContext the current Keycloak context, never null
     * @param realm the realm
     */
    void update(IAMShieldContext keycloakContext, RealmModel realm);

    /**
     * Updates the Mapped Diagnostic Context (MDC) with key/value pairs based on the current Keycloak context.
     * This method is called when a Keycloak Session is set and when the client property of the Keycloak context
     * is updated.
     *
     * @param keycloakContext the current Keycloak context, never null
     * @param client the client
     */
    void update(IAMShieldContext keycloakContext, ClientModel client);

    /**
     * Updates the Mapped Diagnostic Context (MDC) with key/value pairs based on the current Keycloak context.
     * This method is called when a Keycloak Session is set and when the organization property of the Keycloak context
     * is updated.
     *
     * @param keycloakContext the current Keycloak context, never null
     * @param organization the organization
     */
    void update(IAMShieldContext keycloakContext, OrganizationModel organization);

    /**
     * Updates the Mapped Diagnostic Context (MDC) with key/value pairs based on the current Keycloak context.
     * This method is called when a Keycloak Session is set and when the user session property of the Keycloak context
     * is updated.
     *
     * @param keycloakContext the current Keycloak context, never null
     * @param userSession the user session
     */
    void update(IAMShieldContext keycloakContext, UserSessionModel userSession);

}
