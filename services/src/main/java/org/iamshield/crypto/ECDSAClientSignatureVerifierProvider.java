package org.iamshield.crypto;

import org.iamshield.common.VerificationException;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.models.ClientModel;
import org.iamshield.models.IAMShieldSession;

public class ECDSAClientSignatureVerifierProvider implements ClientSignatureVerifierProvider {
    private final IAMShieldSession session;
    private final String algorithm;

    public ECDSAClientSignatureVerifierProvider(IAMShieldSession session, String algorithm) {
        this.session = session;
        this.algorithm = algorithm;
    }

    @Override
    public SignatureVerifierContext verifier(ClientModel client, JWSInput input) throws VerificationException {
        return new ClientECDSASignatureVerifierContext(session, client, input);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }
}
