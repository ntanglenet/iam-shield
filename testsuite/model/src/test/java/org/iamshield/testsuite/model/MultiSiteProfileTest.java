package org.iamshield.testsuite.model;

import org.junit.Test;
import org.iamshield.common.Profile;
import org.iamshield.models.SingleUseObjectProvider;
import org.iamshield.models.UserLoginFailureProvider;
import org.iamshield.models.UserSessionProvider;
import org.iamshield.models.sessions.infinispan.PersistentUserSessionProvider;
import org.iamshield.models.sessions.infinispan.remote.RemoteInfinispanAuthenticationSessionProvider;
import org.iamshield.models.sessions.infinispan.remote.RemoteInfinispanSingleUseObjectProvider;
import org.iamshield.models.sessions.infinispan.remote.RemoteUserLoginFailureProvider;
import org.iamshield.sessions.AuthenticationSessionProvider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assume.assumeTrue;

public class MultiSiteProfileTest extends IAMShieldModelTest {

    @Test
    public void testMultiSiteConfiguredCorrectly() {
        assumeTrue(Profile.isFeatureEnabled(Profile.Feature.MULTI_SITE));
        assumeTrue(Profile.isFeatureEnabled(Profile.Feature.PERSISTENT_USER_SESSIONS));

        inComittedTransaction(session -> {
            UserSessionProvider sessions = session.sessions();
            assertThat(sessions, instanceOf(PersistentUserSessionProvider.class));

            AuthenticationSessionProvider authenticationSessionProvider = session.authenticationSessions();
            assertThat(authenticationSessionProvider, instanceOf(RemoteInfinispanAuthenticationSessionProvider.class));

            UserLoginFailureProvider userLoginFailureProvider = session.loginFailures();
            assertThat(userLoginFailureProvider, instanceOf(RemoteUserLoginFailureProvider.class));

            SingleUseObjectProvider singleUseObjectProvider = session.singleUseObjects();
            assertThat(singleUseObjectProvider, instanceOf(RemoteInfinispanSingleUseObjectProvider.class));
        });
    }
}
