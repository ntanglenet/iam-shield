package org.iamshield.forms.login.freemarker.model;

import org.iamshield.credential.CredentialModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.RecoveryAuthnCodesCredentialModel;
import org.iamshield.models.utils.RecoveryAuthnCodesUtils;

import java.util.Optional;

public class RecoveryAuthnCodeInputLoginBean {

    private final int codeNumber;

    public RecoveryAuthnCodeInputLoginBean(IAMShieldSession session, RealmModel realm, UserModel user) {
        Optional<CredentialModel> credentialModelOpt = RecoveryAuthnCodesUtils.getCredential(user);

        RecoveryAuthnCodesCredentialModel recoveryCodeCredentialModel = RecoveryAuthnCodesCredentialModel.createFromCredentialModel(credentialModelOpt.get());

        this.codeNumber = recoveryCodeCredentialModel.getNextRecoveryAuthnCode().get().getNumber();
    }

    public int getCodeNumber() {
        return this.codeNumber;
    }

}
