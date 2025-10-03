package org.iamshield.crypto;

import org.iamshield.models.IAMShieldSession;

public class ServerECDSASignatureSignerContext extends ECDSASignatureSignerContext {

    public ServerECDSASignatureSignerContext(IAMShieldSession session, String algorithm) throws SignatureException {
        super(ServerAsymmetricSignatureSignerContext.getKey(session, algorithm));
    }

    public ServerECDSASignatureSignerContext(KeyWrapper key) {
        super(key);
    }
}
