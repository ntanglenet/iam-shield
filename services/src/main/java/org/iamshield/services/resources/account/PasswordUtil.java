package org.iamshield.services.resources.account;

import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.PasswordCredentialModel;

public class PasswordUtil {

    private final UserModel user;

    @Deprecated
    public PasswordUtil(IAMShieldSession session, UserModel user) {
        this.user = user;
    }

    public PasswordUtil(UserModel user) {
        this.user = user;
    }

    /**
     * @deprecated Instead, use {@link #isConfigured()}
     */
    @Deprecated
    public boolean isConfigured(IAMShieldSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
    }

    public boolean isConfigured() {
        return user.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
    }

    public void update() {

    }

}
