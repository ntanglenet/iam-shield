package org.iamshield.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.events.EventType;
import org.iamshield.representations.idm.EventRepresentation;
import org.iamshield.testframework.annotations.InjectEvents;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.events.Events;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.remote.timeoffset.InjectTimeOffSet;
import org.iamshield.testframework.remote.timeoffset.TimeOffSet;

@IAMShieldIntegrationTest
public class EventsTest {

    @InjectRealm
    private ManagedRealm realm;

    @InjectEvents
    private Events events;

    @InjectOAuthClient
    private OAuthClient oAuthClient;

    @InjectTimeOffSet
    TimeOffSet timeOffSet;

    @Test
    public void testFailedLogin() {
        oAuthClient.doPasswordGrantRequest("invalid", "invalid");

        EventRepresentation event = events.poll();
        Assertions.assertEquals(EventType.LOGIN_ERROR.name(), event.getType());
        Assertions.assertEquals("invalid", event.getDetails().get("username"));

        oAuthClient.doPasswordGrantRequest("invalid2", "invalid");

        event = events.poll();
        Assertions.assertEquals(EventType.LOGIN_ERROR.name(), event.getType());
        Assertions.assertEquals("invalid2", event.getDetails().get("username"));
    }

    @Test
    public void testTimeOffset() {
        timeOffSet.set(60);

        oAuthClient.doClientCredentialsGrantAccessTokenRequest();

        Assertions.assertEquals(EventType.CLIENT_LOGIN.name(), events.poll().getType());
    }

    @Test
    public void testClientLogin() {
        oAuthClient.doClientCredentialsGrantAccessTokenRequest();

        Assertions.assertEquals(EventType.CLIENT_LOGIN.name(), events.poll().getType());
    }

}
