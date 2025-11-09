package org.iamshield.forms.login.freemarker.model;

import org.iamshield.common.util.Time;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.PasswordPolicy;
import org.iamshield.models.utils.RecoveryAuthnCodesUtils;

import java.util.List;

public class RecoveryAuthnCodesBean {

    private final List<String> generatedRecoveryAuthnCodesList;
    private final long generatedAt;

    public RecoveryAuthnCodesBean() {
        this.generatedRecoveryAuthnCodesList = RecoveryAuthnCodesUtils.generateRawCodes();
        this.generatedAt = Time.currentTimeMillis();
    }

    public List<String> getGeneratedRecoveryAuthnCodesList() {
        return this.generatedRecoveryAuthnCodesList;
    }

    public String getGeneratedRecoveryAuthnCodesAsString() {
        return String.join(",", this.generatedRecoveryAuthnCodesList);
    }

    public long getGeneratedAt() {
        return generatedAt;
    }

}
