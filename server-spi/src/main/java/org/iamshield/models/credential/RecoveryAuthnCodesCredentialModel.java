package org.iamshield.models.credential;

import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.iamshield.common.util.Base64;
import org.iamshield.credential.CredentialMetadata;
import org.iamshield.credential.CredentialModel;
import org.iamshield.models.PasswordPolicy;
import org.iamshield.models.credential.dto.RecoveryAuthnCodeRepresentation;
import org.iamshield.models.credential.dto.RecoveryAuthnCodesCredentialData;
import org.iamshield.models.credential.dto.RecoveryAuthnCodesSecretData;
import org.iamshield.models.utils.RecoveryAuthnCodesUtils;
import org.iamshield.util.JsonSerialization;

import java.io.IOException;
import java.util.List;

public class RecoveryAuthnCodesCredentialModel extends CredentialModel {

    public static final String TYPE = "recovery-authn-codes";

    public static final String RECOVERY_CODES_NUMBER_USED = "recovery-codes-number-used";
    public static final String RECOVERY_CODES_NUMBER_REMAINING = "recovery-codes-number-remaining";
    public static final String RECOVERY_CODES_GENERATE_NEW_CODES = "recovery-codes-generate-new-codes";

    private final RecoveryAuthnCodesCredentialData credentialData;
    private final RecoveryAuthnCodesSecretData secretData;

    private RecoveryAuthnCodesCredentialModel(RecoveryAuthnCodesCredentialData credentialData,
            RecoveryAuthnCodesSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    public Optional<RecoveryAuthnCodeRepresentation> getNextRecoveryAuthnCode() {
        if (allCodesUsed()) {
            return Optional.empty();
        }
        return Optional.of(this.secretData.getCodes().get(0));
    }

    public boolean allCodesUsed() {
        return this.secretData.getCodes().isEmpty();
    }

    public void removeRecoveryAuthnCode() {
        try {
            this.secretData.removeNextBackupCode();
            this.credentialData.setRemainingCodes(this.secretData.getCodes().size());
            this.setSecretData(JsonSerialization.writeValueAsString(this.secretData));
            this.setCredentialData(JsonSerialization.writeValueAsString(this.credentialData));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static RecoveryAuthnCodesCredentialModel createFromValues(List<String> originalGeneratedCodes, long generatedAt,
                                                                     String userLabel) {
        RecoveryAuthnCodesSecretData secretData;
        RecoveryAuthnCodesCredentialData credentialData;
        RecoveryAuthnCodesCredentialModel model;

        try {
            List<RecoveryAuthnCodeRepresentation> recoveryCodes = IntStream.range(0, originalGeneratedCodes.size())
                    .mapToObj(i -> new RecoveryAuthnCodeRepresentation(i + 1,
                            Base64.encodeBytes(RecoveryAuthnCodesUtils.hashRawCode(originalGeneratedCodes.get(i)))))
                    .collect(Collectors.toList());
            secretData = new RecoveryAuthnCodesSecretData(recoveryCodes);
            credentialData = new RecoveryAuthnCodesCredentialData(null,
                    RecoveryAuthnCodesUtils.NOM_ALGORITHM_TO_HASH, recoveryCodes.size(), recoveryCodes.size());
            model = new RecoveryAuthnCodesCredentialModel(credentialData, secretData);
            model.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            model.setSecretData(JsonSerialization.writeValueAsString(secretData));
            model.setCreatedDate(generatedAt);
            model.setType(TYPE);

            if (userLabel != null) {
                model.setUserLabel(userLabel);
            }
            return model;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static RecoveryAuthnCodesCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        RecoveryAuthnCodesCredentialData credentialData;
        RecoveryAuthnCodesSecretData secretData = null;
        RecoveryAuthnCodesCredentialModel newModel;
        try {
            credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(),
                    RecoveryAuthnCodesCredentialData.class);
            secretData = JsonSerialization.readValue(credentialModel.getSecretData(), RecoveryAuthnCodesSecretData.class);
            newModel = new RecoveryAuthnCodesCredentialModel(credentialData, secretData);
            newModel.setUserLabel(credentialModel.getUserLabel());
            newModel.setCreatedDate(credentialModel.getCreatedDate());
            newModel.setType(TYPE);
            newModel.setId(credentialModel.getId());
            newModel.setSecretData(credentialModel.getSecretData());
            newModel.setCredentialData(credentialModel.getCredentialData());
            return newModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
