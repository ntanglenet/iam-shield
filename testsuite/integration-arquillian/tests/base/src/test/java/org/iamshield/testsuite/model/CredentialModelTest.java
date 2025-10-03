package org.iamshield.testsuite.model;

import jakarta.persistence.EntityManager;
import org.junit.Test;
import org.iamshield.connections.jpa.JpaConnectionProvider;
import org.iamshield.credential.CredentialModel;
import org.iamshield.models.IAMShieldSession;
import org.iamshield.models.RealmModel;
import org.iamshield.models.UserModel;
import org.iamshield.models.credential.OTPCredentialModel;
import org.iamshield.models.jpa.entities.CredentialEntity;
import org.iamshield.models.utils.IAMShieldModelUtils;
import org.iamshield.representations.idm.RealmRepresentation;
import org.iamshield.testsuite.AbstractTestRealmIAMShieldTest;
import org.iamshield.testsuite.Assert;
import org.iamshield.testsuite.arquillian.annotation.ModelTest;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CredentialModelTest extends AbstractTestRealmIAMShieldTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {

    }


    @Test
    @ModelTest
    public void testCredentialCRUD(IAMShieldSession session) throws Exception {
        AtomicReference<String> passwordId = new AtomicReference<>();
        AtomicReference<String> otp1Id = new AtomicReference<>();
        AtomicReference<String> otp2Id = new AtomicReference<>();

        IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            currentSession.getContext().setRealm(realm);

            UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");
            List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                    .collect(Collectors.toList());
            Assert.assertEquals(1, list.size());
            passwordId.set(list.get(0).getId());

            // Create 2 OTP credentials (password was already created)
            CredentialModel otp1 = OTPCredentialModel.createFromPolicy(realm, "secret1", "label1");
            CredentialModel otp2 = OTPCredentialModel.createFromPolicy(realm, "secret2", "label2");
            otp1 = user.credentialManager().createStoredCredential(otp1);
            otp2 = user.credentialManager().createStoredCredential(otp2);
            otp1Id.set(otp1.getId());
            otp2Id.set(otp2.getId());
        });

        try {

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

                // Assert priorities: password, otp1, otp2
                List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                        .collect(Collectors.toList());
                assertOrder(list, passwordId.get(), otp1Id.get(), otp2Id.get());

                // Assert can't move password when newPreviousCredential not found
                Assert.assertFalse(user.credentialManager().moveStoredCredentialTo(passwordId.get(), "not-known"));

                // Assert can't move credential when not found
                Assert.assertFalse(user.credentialManager().moveStoredCredentialTo("not-known", otp2Id.get()));

                // Move otp2 up 1 position
                Assert.assertTrue(user.credentialManager().moveStoredCredentialTo(otp2Id.get(), passwordId.get()));
            });

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

                // Assert priorities: password, otp2, otp1
                List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                        .collect(Collectors.toList());
                assertOrder(list, passwordId.get(), otp2Id.get(), otp1Id.get());

                // Move otp2 to the top
                Assert.assertTrue(user.credentialManager().moveStoredCredentialTo(otp2Id.get(), null));
            });

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

                // Assert priorities: otp2, password, otp1
                List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                        .collect(Collectors.toList());
                assertOrder(list, otp2Id.get(), passwordId.get(), otp1Id.get());

                // Move password down
                Assert.assertTrue(user.credentialManager().moveStoredCredentialTo(passwordId.get(), otp1Id.get()));
            });

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

                // Assert priorities: otp2, otp1, password
                List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                        .collect(Collectors.toList());
                assertOrder(list, otp2Id.get(), otp1Id.get(), passwordId.get());

                // Remove otp2 down two positions
                Assert.assertTrue(user.credentialManager().moveStoredCredentialTo(otp2Id.get(), passwordId.get()));
            });

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

                // Assert priorities: otp2, otp1, password
                List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                        .collect(Collectors.toList());
                assertOrder(list, otp1Id.get(), passwordId.get(), otp2Id.get());

                // Remove password
                Assert.assertTrue(user.credentialManager().removeStoredCredentialById(passwordId.get()));
            });

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

                // Assert priorities: otp2, password
                List<CredentialModel> list = user.credentialManager().getStoredCredentialsStream()
                        .collect(Collectors.toList());
                assertOrder(list, otp1Id.get(), otp2Id.get());
            });

        } finally {
            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");
                user.credentialManager().removeStoredCredentialById(otp1Id.get());
                user.credentialManager().removeStoredCredentialById(otp2Id.get());
            });
        }
    }

    @Test
    @ModelTest
    public void testCredentialUpdateWithDuplicateLabel(IAMShieldSession session) {
        AtomicReference<String> otp1Id = new AtomicReference<>();
        AtomicReference<String> otp2Id = new AtomicReference<>();

        IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
            RealmModel realm = currentSession.realms().getRealmByName("test");
            currentSession.getContext().setRealm(realm);

            UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");

            // Create 2 OTP credentials with the same label (as it was in pre-26.3)
            CredentialModel otp1 = OTPCredentialModel.createFromPolicy(realm, "secret1", "label1");
            CredentialModel otp2 = OTPCredentialModel.createFromPolicy(realm, "secret2", "label2");
            otp1 = user.credentialManager().createStoredCredential(otp1);
            otp2 = user.credentialManager().createStoredCredential(otp2);
            otp1Id.set(otp1.getId());
            otp2Id.set(otp2.getId());

            // Fake a duplicate label by setting the label directly on the JPA level
            EntityManager em = currentSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            CredentialEntity credentialEntity = em.find(CredentialEntity.class, otp2.getId());
            credentialEntity.setUserLabel("label1");
        });

        try {

            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");
                CredentialModel credential = user.credentialManager().getStoredCredentialById(otp1Id.get());

                // must not throw an exception even when the two labels are the same
                credential.setSecretData("newsecret");
                user.credentialManager().updateStoredCredential(credential);
            });

        } finally {
            IAMShieldModelUtils.runJobInTransaction(session.getIAMShieldSessionFactory(), (IAMShieldSession currentSession) -> {
                RealmModel realm = currentSession.realms().getRealmByName("test");
                currentSession.getContext().setRealm(realm);
                UserModel user = currentSession.users().getUserByUsername(realm, "test-user@localhost");
                user.credentialManager().removeStoredCredentialById(otp1Id.get());
                user.credentialManager().removeStoredCredentialById(otp2Id.get());
            });
        }

    }


    private void assertOrder(List<CredentialModel> creds, String... expectedIds) {
        Assert.assertEquals(expectedIds.length, creds.size());

        if (creds.isEmpty()) return;

        for (int i=0 ; i<expectedIds.length ; i++) {
            Assert.assertEquals(creds.get(i).getId(), expectedIds[i]);
        }
    }

}
