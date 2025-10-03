package org.iamshield.test.examples;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.iamshield.events.email.EmailEventListenerProviderFactory;
import org.iamshield.testframework.annotations.InjectRealm;
import org.iamshield.testframework.annotations.InjectUser;
import org.iamshield.testframework.annotations.IAMShieldIntegrationTest;
import org.iamshield.testframework.mail.MailServer;
import org.iamshield.testframework.mail.annotations.InjectMailServer;
import org.iamshield.testframework.oauth.OAuthClient;
import org.iamshield.testframework.oauth.annotations.InjectOAuthClient;
import org.iamshield.testframework.realm.ManagedRealm;
import org.iamshield.testframework.realm.ManagedUser;
import org.iamshield.testframework.realm.RealmConfig;
import org.iamshield.testframework.realm.RealmConfigBuilder;
import org.iamshield.testframework.realm.UserConfig;
import org.iamshield.testframework.realm.UserConfigBuilder;

import java.util.Map;

@IAMShieldIntegrationTest
public class EmailTest {

    @InjectRealm(config = EmailSenderRealmConfig.class)
    ManagedRealm realm;

    @InjectUser(config = UserWithEmail.class)
    ManagedUser user;

    @InjectMailServer
    MailServer mail;

    @InjectOAuthClient
    OAuthClient oAuthClient;

    @Test
    public void testEmail() throws MessagingException {
        oAuthClient.doPasswordGrantRequest(user.getUsername(), "invalid");

        Map<String, String> smtpServer = realm.admin().toRepresentation().getSmtpServer();
        Assertions.assertEquals("auto@keycloak.org", smtpServer.get("from"));
        Assertions.assertEquals("localhost", smtpServer.get("host"));
        Assertions.assertEquals("3025", smtpServer.get("port"));

        mail.waitForIncomingEmail(1);
        MimeMessage lastReceivedMessage = mail.getLastReceivedMessage();
        Assertions.assertEquals("Login error", lastReceivedMessage.getSubject());
        MatcherAssert.assertThat(lastReceivedMessage.getMessageID(), Matchers.endsWith("@keycloak.org>"));
    }

    public static class EmailSenderRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            return realm.eventsListeners(EmailEventListenerProviderFactory.ID);
        }
    }

    public static class UserWithEmail implements UserConfig {

        @Override
        public UserConfigBuilder configure(UserConfigBuilder user) {
            return user.username("test").email("test@local").password("password").emailVerified(true);
        }
    }

}
