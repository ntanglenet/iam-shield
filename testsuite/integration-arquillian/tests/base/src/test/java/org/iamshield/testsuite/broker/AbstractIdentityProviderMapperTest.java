package org.iamshield.testsuite.broker;

import org.junit.Before;
import org.iamshield.admin.client.resource.RealmResource;
import org.iamshield.admin.client.resource.UsersResource;
import org.iamshield.representations.idm.IdentityProviderRepresentation;
import org.iamshield.representations.idm.MappingsRepresentation;
import org.iamshield.representations.idm.RoleRepresentation;
import org.iamshield.representations.idm.UserRepresentation;
import org.iamshield.testsuite.util.UserBuilder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.iamshield.testsuite.admin.ApiUtil.createUserAndResetPasswordWithAdminClient;

/**
 * @author hmlnarik
 * <a href="mailto:external.benjamin.weimer@bosch-si.com">Benjamin Weimer</a>,
 * <a href="mailto:external.martin.idel@bosch.io">Martin Idel</a>,
 */
public abstract class AbstractIdentityProviderMapperTest extends AbstractBaseBrokerTest {

    protected RealmResource realm;

    @Before
    public void addClients() {
        addClientsToProviderAndConsumer();
        realm = adminClient.realm(bc.consumerRealmName());
    }

    protected IdentityProviderRepresentation setupIdentityProvider() {
        log.debug("adding identity provider to realm " + bc.consumerRealmName());

        final IdentityProviderRepresentation idp = bc.setUpIdentityProvider();
        realm.identityProviders().create(idp).close();
        return idp;
    }

    protected IdentityProviderRepresentation setupIdentityProviderDisableUserInfo() {
        log.debug("adding identity provider to realm " + bc.consumerRealmName());

        final IdentityProviderRepresentation idp = bc.setUpIdentityProvider();
        idp.getConfig().put("disableUserInfo", "true");
        realm.identityProviders().create(idp).close();
        return idp;
    }

    protected void createUserInProviderRealm(Map<String, List<String>> attributes) {
        log.debug("Creating user in realm " + bc.providerRealmName());

        UserRepresentation user = UserBuilder.create()
                .username(bc.getUserLogin())
                .email(bc.getUserEmail())
                .build();
        user.setEmailVerified(true);
        user.setAttributes(attributes);

        this.userId = createUserAndResetPasswordWithAdminClient(adminClient.realm(bc.providerRealmName()), user, bc.getUserPassword());
    }

    protected UserRepresentation findUser(String realm, String userName, String email) {
        UsersResource consumerUsers = adminClient.realm(realm).users();

        List<UserRepresentation> users = consumerUsers.list();
        assertThat("There must be exactly one user", users, hasSize(1));
        UserRepresentation user = users.get(0);
        assertThat("Username has to match", user.getUsername(), equalTo(userName));
        assertThat("Email has to match", user.getEmail(), equalTo(email));

        MappingsRepresentation roles = consumerUsers.get(user.getId()).roles().getAll();

        List<String> realmRoles = roles.getRealmMappings().stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
        user.setRealmRoles(realmRoles);

        Map<String, List<String>> clientRoles = new HashMap<>();
        if (roles.getClientMappings() != null) {
            roles.getClientMappings().forEach((key, value) -> clientRoles.put(key, value.getMappings().stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList())));
        }
        user.setClientRoles(clientRoles);

        return user;
    }
}
