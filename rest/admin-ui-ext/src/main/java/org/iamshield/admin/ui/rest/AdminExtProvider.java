package org.iamshield.admin.ui.rest;

import org.iamshield.Config;
import org.iamshield.common.Profile;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.IAMShieldSessionFactory;
import org.iamshield.models.RealmModel;
import org.iamshield.provider.EnvironmentDependentProviderFactory;
import org.iamshield.services.resources.admin.AdminEventBuilder;
import org.iamshield.services.resources.admin.ext.AdminRealmResourceProvider;
import org.iamshield.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.iamshield.services.resources.admin.fgap.AdminPermissionEvaluator;

public final class AdminExtProvider implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider, EnvironmentDependentProviderFactory {
    public AdminRealmResourceProvider create(IAMShieldSession session) {
        return this;
    }

    public void init(Config.Scope config) {
    }

    public void postInit(IAMShieldSessionFactory factory) {
    }

    public void close() {
    }

    public String getId() {
        return "ui-ext";
    }

    public Object getResource(IAMShieldSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new AdminExtResource(session, realm, auth, adminEvent);
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.ADMIN_V2);
    }
}
