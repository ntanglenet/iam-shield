package org.iamshield.authentication;

import org.iamshield.credential.CredentialModel;
import org.iamshield.credential.CredentialProvider;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;

import java.util.List;
import java.util.stream.Collectors;

public interface CredentialValidator<T extends CredentialProvider> {
    T getCredentialProvider(IAMShieldSession session);
    default List<CredentialModel> getCredentials(IAMShieldSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(getCredentialProvider(session).getType())
                .collect(Collectors.toList());
    }
    default String getType(IAMShieldSession session) {
        return getCredentialProvider(session).getType();
    }
}
