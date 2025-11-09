package org.iamshield.social.facebook;

import java.util.Optional;

import org.iamshield.broker.oidc.OIDCIdentityProviderConfig;
import org.iamshield.models.IdentityProviderModel;

public class FacebookIdentityProviderConfig extends OIDCIdentityProviderConfig {

    public FacebookIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public FacebookIdentityProviderConfig() {
    }

    public String getFetchedFields() {
        return Optional.ofNullable(getConfig().get("fetchedFields"))
                .map(fieldsConfig -> fieldsConfig.replaceAll("\\s+",""))
                .orElse("");
    }

    public void setFetchedFields(final String fetchedFields) {
        getConfig().put("fetchedFields", fetchedFields);
    }
}
