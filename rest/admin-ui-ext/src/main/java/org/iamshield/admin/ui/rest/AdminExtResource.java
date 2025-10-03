package org.iamshield.admin.ui.rest;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.services.resources.admin.AdminEventBuilder;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

import jakarta.ws.rs.Path;

public final class AdminExtResource {
    private IAMShieldSession session;
    private RealmModel realm;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    public AdminExtResource(IAMShieldSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent;
    }

    @Path("/authentication-management")
    public AuthenticationManagementResource authenticationManagement() {
        return new AuthenticationManagementResource(session, realm, auth);
    }

    @Path("/brute-force-user")
    public BruteForceUsersResource bruteForceUsers() {
        return new BruteForceUsersResource(session, realm, auth);
    }

    @Path("/available-roles")
    public AvailableRoleMappingResource availableRoles() {
        return new AvailableRoleMappingResource(session, realm, auth);
    }

    @Path("/available-event-listeners")
    public AvailableEventListenersResource availableEventListeners() {
        return new AvailableEventListenersResource(session, auth);
    }

    @Path("/effective-roles")
    public EffectiveRoleMappingResource effectiveRoles() {
        return new EffectiveRoleMappingResource(session, realm, auth);
    }

    @Path("/sessions")
    public SessionsResource sessions() {
        return new SessionsResource(session, realm, auth);
    }

    @Path("/realms")
    public UIRealmsResource realms() {
        return new UIRealmsResource(session, auth);
    }

    @Path("/")
    public UIRealmResource realm() {
        return new UIRealmResource(session, auth, adminEvent);
    }
}
