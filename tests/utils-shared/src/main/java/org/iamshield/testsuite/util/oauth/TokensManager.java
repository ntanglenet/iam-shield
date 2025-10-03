package org.iamshield.testsuite.util.oauth;

import org.iamshield.TokenVerifier;
import org.iamshield.common.VerificationException;
import org.iamshield.crypto.Algorithm;
import org.iamshield.crypto.AsymmetricSignatureVerifierContext;
import org.iamshield.crypto.KeyWrapper;
import org.iamshield.crypto.ServerECDSASignatureVerifierContext;
import org.iamshield.jose.jws.JWSInput;
import org.iamshield.representations.JsonWebToken;

public class TokensManager {

    private final KeyManager keyManager;

    TokensManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public <T extends JsonWebToken> T verifyToken(String token, Class<T> clazz) {
        try {
            TokenVerifier<T> verifier = TokenVerifier.create(token, clazz);
            String kid = verifier.getHeader().getKeyId();
            String algorithm = verifier.getHeader().getAlgorithm().name();
            KeyWrapper key = keyManager.getPublicKey(algorithm, kid);
            AsymmetricSignatureVerifierContext verifierContext;
            switch (algorithm) {
                case Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 ->
                        verifierContext = new ServerECDSASignatureVerifierContext(key);
                default -> verifierContext = new AsymmetricSignatureVerifierContext(key);
            }
            verifier.verifierContext(verifierContext);
            verifier.verify();
            return verifier.getToken();
        } catch (VerificationException e) {
            throw new RuntimeException("Failed to decode token", e);
        }
    }

    public <T extends JsonWebToken> T parseToken(String token, Class<T> clazz) {
        try {
            return new JWSInput(token).readJsonContent(clazz);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
