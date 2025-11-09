package org.iamshield.tests.admin.user;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.events.AdminEventAssertion;
import org.iamshield.testframework.realm.UserConfigBuilder;
import org.iamshield.tests.utils.admin.ApiUtil;

import static org.junit.jupiter.api.Assertions.assertEquals;

@IAMShieldIntegrationTest
public class UserDeleteTest extends AbstractUserTest {

    @Test
    public void delete() {
        String userId = ApiUtil.getCreatedId(managedRealm.admin().users().create(UserConfigBuilder.create().username("user1").email("user1@localhost.com").build()));
        AdminEventAssertion.assertSuccess(adminEvents.poll());
        deleteUser(userId);
    }

    @Test
    public void deleteNonExistent() {
        try (Response response = managedRealm.admin().users().delete("does-not-exist")) {
            assertEquals(404, response.getStatus());
        }
        Assertions.assertNull(adminEvents.poll());
    }
}
