package org.iamshield.testsuite.model.user;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.iamshield.component.ComponentModel;
import org.iamshield.models.Constants;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.RealmProvider;
import org.iamshield.models.UserModel;
import org.iamshield.models.UserProvider;
import org.iamshield.storage.UserStorageProvider;
import org.iamshield.storage.UserStorageProviderModel;
import org.iamshield.testsuite.federation.UserPropertyFileStorage;
import org.iamshield.testsuite.federation.UserPropertyFileStorage.UserPropertyFileStorageCall;
import org.iamshield.testsuite.federation.UserPropertyFileStorageFactory;
import org.iamshield.testsuite.model.IAMShieldModelTest;

import org.iamshield.testsuite.model.RequireProvider;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assume.assumeThat;

/**
 * @author mhajas
 */
@RequireProvider(UserProvider.class)
@RequireProvider(RealmProvider.class)
@RequireProvider(value = UserStorageProvider.class, only = UserPropertyFileStorageFactory.PROVIDER_ID)
public class UserPaginationTest extends IAMShieldModelTest {

    private String realmId;
    private String userFederationId1;
    private String userFederationId2;

    @Override
    public void createEnvironment(IAMShieldSession s) {
        RealmModel realm = createRealm(s, "realm");
        s.getContext().setRealm(realm);
        realm.setDefaultRole(s.roles().addRealmRole(realm, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realm.getName()));
        this.realmId = realm.getId();

        getParameters(UserStorageProviderModel.class).forEach(fs -> inComittedTransaction(session -> {
            assumeThat("Cannot handle more than 2 user federation provider", userFederationId2, Matchers.nullValue());

            fs.setParentId(realmId);

            ComponentModel res = realm.addComponentModel(fs);
            if (userFederationId1 == null) {
                userFederationId1 = res.getId();
            } else {
                userFederationId2 = res.getId();
            }

            log.infof("Added %s user federation provider: %s", fs.getName(), res.getId());
        }));
    }

    @Override
    public void cleanEnvironment(IAMShieldSession s) {
        RealmModel realm = s.realms().getRealm(realmId);
        s.getContext().setRealm(realm);
        s.realms().removeRealm(realmId);
    }

    @Test
    public void testNoPaginationCalls() {
        List<UserModel> list = withRealm(realmId, (session, realm) ->
                session.users().searchForUserStream(realm, Map.of(UserModel.SEARCH, ""), 0, Constants.DEFAULT_MAX_RESULTS) // Default values used in UsersResource
                        .collect(Collectors.toList()));

        assertThat(list, hasSize(8));

        expectedStorageCalls(
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 0, Constants.DEFAULT_MAX_RESULTS)),
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 0, Constants.DEFAULT_MAX_RESULTS - 4))
        );
    }

    @Test
    public void testPaginationStarting0() {
        List<UserModel> list = withRealm(realmId, (session, realm) ->
                session.users().searchForUserStream(realm, Map.of(UserModel.SEARCH, ""), 0, 6)
                        .collect(Collectors.toList()));

        assertThat(list, hasSize(6));


        expectedStorageCalls(
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 0, 6)),
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 0, 2))
        );
    }

    @Test
    public void testPaginationFirstResultInFirstProvider() {
        List<UserModel> list = withRealm(realmId, (session, realm) ->
                session.users().searchForUserStream(realm, Map.of(UserModel.SEARCH, ""), 1, 6)
                        .collect(Collectors.toList()));
        assertThat(list, hasSize(6));

        expectedStorageCalls(
                Arrays.asList(new UserPropertyFileStorageCall(UserPropertyFileStorage.COUNT_SEARCH_METHOD, null, null), new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 1, 6)),
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 0, 3))
        );
    }

    @Test
    public void testPaginationFirstResultIsExactlyTheAmountOfUsersInTheFirstProvider() {
        List<UserModel> list = withRealm(realmId, (session, realm) ->
                session.users().searchForUserStream(realm, Map.of(UserModel.SEARCH, ""), 4, 6)
                        .collect(Collectors.toList()));
        assertThat(list, hasSize(4));

        expectedStorageCalls(
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.COUNT_SEARCH_METHOD, null, null)),
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 0, 6))
        );
    }

    @Test
    public void testPaginationFirstResultIsInSecondProvider() {
        List<UserModel> list = withRealm(realmId, (session, realm) ->
                session.users().searchForUserStream(realm, Map.of(UserModel.SEARCH, ""), 5, 6)
                .collect(Collectors.toList()));

        assertThat(list, hasSize(3));

        expectedStorageCalls(
                Collections.singletonList(new UserPropertyFileStorageCall(UserPropertyFileStorage.COUNT_SEARCH_METHOD, null, null)),
                Arrays.asList(new UserPropertyFileStorageCall(UserPropertyFileStorage.COUNT_SEARCH_METHOD, null, null), new UserPropertyFileStorageCall(UserPropertyFileStorage.SEARCH_METHOD, 1, 6))
        );
    }

    private void expectedStorageCalls(final List<UserPropertyFileStorageCall> roCalls, final List<UserPropertyFileStorageCall> rwCalls) {
        assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId1), hasSize(roCalls.size()));

        int i = 0;
        for (UserPropertyFileStorageCall call : roCalls) {
            assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId1).get(i).getMethod(), equalTo(call.getMethod()));
            assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId1).get(i).getFirst(), equalTo(call.getFirst()));
            assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId1).get(i).getMax(), equalTo(call.getMax()));
            i++;
        }

        assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId2), hasSize(rwCalls.size()));

        i = 0;
        for (UserPropertyFileStorageCall call : rwCalls) {
            assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId2).get(i).getMethod(), equalTo(call.getMethod()));
            assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId2).get(i).getFirst(), equalTo(call.getFirst()));
            assertThat(UserPropertyFileStorage.storageCalls.get(userFederationId2).get(i).getMax(), equalTo(call.getMax()));
            i++;
        }

        UserPropertyFileStorage.storageCalls.clear();
    }

}
