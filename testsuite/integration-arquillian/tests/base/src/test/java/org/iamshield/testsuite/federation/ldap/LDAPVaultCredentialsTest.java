package org.iamshield.testsuite.federation.ldap;

import org.junit.ClassRule;
import org.iamshield.testsuite.arquillian.annotation.EnableVault;
import org.iamshield.testsuite.util.LDAPRule;
import org.iamshield.testsuite.util.LDAPTestConfiguration;

import java.util.Map;

import static org.iamshield.models.LDAPConstants.BIND_CREDENTIAL;

/**
 * @author mhajas
 */
@EnableVault
public class LDAPVaultCredentialsTest extends LDAPSyncTest {

    private static final String VAULT_EXPRESSION = "${vault.ldap_bindCredential}";

    @ClassRule
    public static LDAPRule ldapRule = new LDAPRule() {
        @Override
        public Map<String, String> getConfig() {

            Map<String, String> config = super.getConfig();
            // Replace secret with vault expression
            config.put(BIND_CREDENTIAL, VAULT_EXPRESSION);
            return config;
        }
    }.assumeTrue(LDAPTestConfiguration::isStartEmbeddedLdapServer);

    @Override
    protected LDAPRule getLDAPRule() {
        return ldapRule;
    }
}
