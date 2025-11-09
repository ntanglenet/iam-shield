package org.iamshield.logging;

import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldContext;
import org.iamshield.models.OrganizationModel;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserSessionModel;
import org.iamshield.sessions.AuthenticationSessionModel;

public class NoopMappedDiagnosticContextProvider implements MappedDiagnosticContextProvider {

    @Override
    public void update(IAMShieldContext keycloakContext, AuthenticationSessionModel session) {
        // no-op
    }

    @Override
    public void update(IAMShieldContext keycloakContext, RealmModel realm) {
        // no-op
    }

    @Override
    public void update(IAMShieldContext keycloakContext, ClientModel client) {
        // no-op
    }

    @Override
    public void update(IAMShieldContext keycloakContext, OrganizationModel organization) {
        // no-op
    }

    @Override
    public void update(IAMShieldContext keycloakContext, UserSessionModel userSession) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }
}
