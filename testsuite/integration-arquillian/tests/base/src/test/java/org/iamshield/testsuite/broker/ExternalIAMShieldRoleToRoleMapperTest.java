package org.iamshield.testsuite.broker;

import static org.iamshield.models.IdentityProviderMapperSyncMode.FORCE;
import static org.iamshield.models.IdentityProviderMapperSyncMode.IMPORT;
import static org.iamshield.models.IdentityProviderMapperSyncMode.LEGACY;

import org.junit.Before;
import org.junit.Test;
import org.iamshield.admin.client.resource.UserResource;
import org.iamshield.broker.oidc.mappers.ExternalIAMShieldRoleToRoleMapper;
import org.iamshield.broker.provider.ConfigConstants;
import org.iamshield.models.IdentityProviderMapperModel;
import org.iamshield.models.IdentityProviderMapperSyncMode;
import org.iamshield.representations.idm.IdentityProviderMapperRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;

import com.google.common.collect.ImmutableMap;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:external.martin.idel@bosch.io">Martin Idel</a>,
 * <a href="mailto:daniel.fesenmeyer@bosch.io">Daniel Fesenmeyer</a>
 */
public class ExternalIAMShieldRoleToRoleMapperTest extends AbstractRoleMapperTest {
    private boolean deleteRoleFromUser = true;

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return new KcOidcBrokerConfiguration();
    }

    @Before
    public void setupRealm() {
        super.addClients();
    }

    @Test
    public void mapperGrantsRoleOnFirstLogin() {
        createMapperThenLoginAsUserTwiceWithExternalIAMShieldRoleToRoleMapper(IMPORT);

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    @Test
    public void updateBrokeredUserDoesNotGrantRoleInLegacyMode() {
        loginAsUserThenCreateMapperAndLoginAgainWithExternalIAMShieldRoleToRoleMapper(LEGACY);

        assertThatRoleHasNotBeenAssignedInConsumerRealm();
    }

    @Test
    public void updateBrokeredUserGrantsRoleInForceMode() {
        loginAsUserThenCreateMapperAndLoginAgainWithExternalIAMShieldRoleToRoleMapper(FORCE);

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    @Test
    public void updateBrokeredUserMatchDeletesRoleInForceMode() {
        createMapperThenLoginAsUserTwiceWithExternalIAMShieldRoleToRoleMapper(FORCE);

        assertThatRoleHasNotBeenAssignedInConsumerRealm();
    }

    @Test
    public void updateBrokeredUserMatchDoesNotDeleteRoleInLegacyMode() {
        createMapperThenLoginAsUserTwiceWithExternalIAMShieldRoleToRoleMapper(LEGACY);

        assertThatRoleHasBeenAssignedInConsumerRealm();
    }

    private void createMapperThenLoginAsUserTwiceWithExternalIAMShieldRoleToRoleMapper(
            IdentityProviderMapperSyncMode syncMode) {
        loginAsUserTwiceWithMapper(syncMode, false, Collections.emptyMap());
    }

    private void loginAsUserThenCreateMapperAndLoginAgainWithExternalIAMShieldRoleToRoleMapper(
            IdentityProviderMapperSyncMode syncMode) {
        deleteRoleFromUser = false;
        loginAsUserTwiceWithMapper(syncMode, true, Collections.emptyMap());
    }

    @Override
    protected void createMapperInIdp(IdentityProviderMapperSyncMode syncMode, String roleValue) {
        IdentityProviderMapperRepresentation externalRoleToRoleMapper = new IdentityProviderMapperRepresentation();
        externalRoleToRoleMapper.setName("external-keycloak-role-mapper");
        externalRoleToRoleMapper.setIdentityProviderMapper(ExternalIAMShieldRoleToRoleMapper.PROVIDER_ID);
        externalRoleToRoleMapper.setConfig(ImmutableMap.<String, String> builder()
                .put(IdentityProviderMapperModel.SYNC_MODE, syncMode.toString())
                .put("external.role", ROLE_USER)
                .put(ConfigConstants.ROLE, roleValue)
                .build());

        persistMapper(externalRoleToRoleMapper);
    }

    @Override
    public void updateUser() {
        if (deleteRoleFromUser) {
            RoleRepresentation role = adminClient.realm(bc.providerRealmName()).roles().get(ROLE_USER).toRepresentation();
            UserResource userResource = adminClient.realm(bc.providerRealmName()).users().get(userId);
            userResource.roles().realmLevel().remove(Collections.singletonList(role));
        }
    }

    @Override
    protected Map<String, List<String>> createUserConfigForRole(String roleValue) {
        return Collections.emptyMap();
    }
}
