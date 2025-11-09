package org.iamshield.crypto.fips.test;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.iamshield.common.crypto.CryptoConstants;
import org.iamshield.crypto.fips.FIPSAesKeyWrapAlgorithmProvider;
import org.iamshield.common.crypto.CryptoIntegration;
import org.iamshield.jose.jwe.alg.JWEAlgorithmProvider;
import org.iamshield.rule.CryptoInitRule;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FIPS1402UnitTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testFips() throws Exception {
        JWEAlgorithmProvider jweAlg = CryptoIntegration.getProvider().getAlgorithmProvider(JWEAlgorithmProvider.class, CryptoConstants.A128KW);
        Assert.assertEquals(jweAlg.getClass(), FIPSAesKeyWrapAlgorithmProvider.class);
    }
}
