package org.iamshield.tests.admin.identityprovider;

import org.junit.jupiter.api.Assertions;
import org.iamshield.events.admin.OperationType;
import org.iamshield.events.admin.ResourceType;
import org.iamshield.models.IdentityProviderModel;
import org.iamshield.models.utils.StripSecretsUtils;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.testframework.annotations.InjectAdminEvents;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.events.AdminEventAssertion;
import org.iamshield.testframework.events.AdminEvents;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.runonserver.InjectRunOnServer;
import org.iamshield.testframework.remote.runonserver.RunOnServerClient;
import org.iamshield.tests.utils.admin.AdminEventPaths;
import org.iamshield.tests.utils.admin.ApiUtil;

import java.util.Map;

public class AbstractIdentityProviderTest {

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectAdminEvents
    AdminEvents adminEvents;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    protected String create(IdentityProviderRepresentation idpRep) {
        String idpId = ApiUtil.getCreatedId(managedRealm.admin().identityProviders().create(idpRep));
        Assertions.assertNotNull(idpId);

        String secret = idpRep.getConfig() != null ? idpRep.getConfig().get("clientSecret") : null;
        idpRep = StripSecretsUtils.stripSecrets(null, idpRep);
        // if legacy hide on login page attribute was used, the attr will be removed when converted to model
        idpRep.setHideOnLogin(Boolean.parseBoolean(idpRep.getConfig().remove(IdentityProviderModel.LEGACY_HIDE_ON_LOGIN_ATTR)));

        AdminEventAssertion.assertEvent(adminEvents.poll(), OperationType.CREATE, AdminEventPaths.identityProviderPath(idpRep.getAlias()), idpRep, ResourceType.IDENTITY_PROVIDER);

        if (secret != null) {
            idpRep.getConfig().put("clientSecret", secret);
        }

        return idpId;
    }

    protected IdentityProviderRepresentation createRep(String alias, String providerId) {
        return createRep(alias, providerId,true, null);
    }

    protected IdentityProviderRepresentation createRep(String alias, String providerId,boolean enabled, Map<String, String> config) {
        return createRep(alias, alias, providerId, enabled, config);
    }

    protected IdentityProviderRepresentation createRep(String alias, String displayName, String providerId, boolean enabled, Map<String, String> config) {
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();

        idp.setAlias(alias);
        idp.setDisplayName(displayName);
        idp.setProviderId(providerId);
        idp.setEnabled(enabled);
        if (config != null) {
            idp.setConfig(config);
        }
        return idp;
    }

    protected void assertProviderInfo(Map<String, String> info, String id, String name) {
        System.out.println(info);
        Assertions.assertEquals(id, info.get("id"), "id");
        Assertions.assertEquals(name, info.get("name"), "name");
    }
}
