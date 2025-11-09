package org.iamshield.crypto.def.test;

import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.common.crypto.CryptoConstants;
import org.iamshield.crypto.def.AesKeyWrapAlgorithmProvider;
import org.iamshield.jose.jwe.alg.JWEAlgorithmProvider;
import org.iamshield.rule.CryptoInitRule;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultCryptoUnitTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testDefaultCrypto() throws Exception {
        JWEAlgorithmProvider jweAlg = CryptoIntegration.getProvider().getAlgorithmProvider(JWEAlgorithmProvider.class, CryptoConstants.A128KW);
        Assert.assertEquals(jweAlg.getClass(), AesKeyWrapAlgorithmProvider.class);
    }
}
