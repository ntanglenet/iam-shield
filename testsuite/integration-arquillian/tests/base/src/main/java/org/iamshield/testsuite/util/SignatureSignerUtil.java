package org.iamshield.testsuite.util;

import org.iamshield.crypto.Algorithm;
import org.iamshield.crypto.AsymmetricSignatureSignerContext;
import org.iamshield.crypto.KeyWrapper;
import org.iamshield.crypto.ServerECDSASignatureSignerContext;
import org.iamshield.crypto.SignatureSignerContext;

import java.security.PrivateKey;

public class SignatureSignerUtil {

    public static SignatureSignerContext createSigner(PrivateKey privateKey, String kid, String algorithm) {
        return createSigner(privateKey, kid, algorithm, null);
    }

    public static SignatureSignerContext createSigner(PrivateKey privateKey, String kid, String algorithm, String curve) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(algorithm);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(privateKey);
        keyWrapper.setCurve(curve);
        SignatureSignerContext signer;
        switch (algorithm) {
            case Algorithm.ES256:
            case Algorithm.ES384:
            case Algorithm.ES512:
                signer = new ServerECDSASignatureSignerContext(keyWrapper);
                break;
            default:
                signer = new AsymmetricSignatureSignerContext(keyWrapper);
        }
        return signer;
    }
}
